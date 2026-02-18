"""
RAG query and response generation.

Handles:
- Semantic search against ChromaDB
- Context formatting for Claude
- Response generation with citations
"""

import logging
import os
from pathlib import Path
from typing import Optional

from .models import ChatResponse, DocumentChunk, RAGStats, SearchResult, TokenUsage
from .network_tools import NETWORK_TOOLS, execute_tool_sync, get_tools_for_permissions
from .sanitizer import sanitize_context_chunk
from core.chromadb_client import get_chromadb_client, get_documentation_collection

# Configure logger
logger = logging.getLogger(__name__)

# Default settings
DEFAULT_TOP_K = int(os.getenv("RAG_TOP_K", "5"))


class RAGQueryEngine:
    """Handles semantic search and Claude response generation."""

    COLLECTION_NAME = "documentation"

    SYSTEM_PROMPT = """You are a helpful network engineering assistant with access to documentation.
Use the provided context to answer questions accurately. If the context doesn't contain
enough information to fully answer the question, say so and provide what information you can.

When referencing documentation, be specific about where the information comes from.
Keep responses concise and focused on the question asked."""

    SYSTEM_PROMPT_WITH_TOOLS = """You are a helpful network engineering assistant for a Cisco lab environment.

You have access to:
1. Documentation from Cisco PDFs and technical guides
2. Live network tools to query the actual lab devices

The lab has these devices:
- R1, R2, R3, R4: Cisco C8000V routers (IOS-XE 17.13)
- Switch-R1, Switch-R2, Switch-R4: Cisco Cat9kv switches
- Alpine-1, Docker-1: Linux hosts

When asked about current/live network status, USE THE TOOLS to get real data.
When asked about concepts, configuration syntax, or documentation, use the provided documentation context.
For troubleshooting, combine both: check live status AND reference documentation.

Be concise and specific. If you use tools, summarize the key findings."""

    SYSTEM_PROMPT_READONLY = """

You have READ-ONLY access to the network. You can:
- View device status and health
- Execute show commands
- Query documentation

If the user asks for configuration changes, interface remediation, or any write operations,
politely explain that they need admin permissions for those operations. Suggest they contact
their administrator to request the 'run_config_commands' or 'remediate_interfaces' permission."""

    SYSTEM_PROMPT_ADMIN = """

You have ADMIN access to the network. You can:
- All read-only operations (show commands, health checks)
- Send configuration commands to devices
- Remediate interfaces (shutdown, no shutdown, bounce)

IMPORTANT: Always confirm with the user before making configuration changes.
Describe what you're about to do and ask for confirmation before executing write operations."""

    def __init__(
        self,
        chromadb_path: Optional[Path] = None,
        top_k: int = DEFAULT_TOP_K,
    ):
        """
        Initialize the RAG query engine.

        Args:
            chromadb_path: Path to ChromaDB storage directory
            top_k: Number of chunks to retrieve for context
        """
        self.top_k = top_k

        # Initialize ChromaDB using core module
        self._client = get_chromadb_client(chromadb_path)
        self._collection = get_documentation_collection(chromadb_path)

        # Lazy-load services
        self._embedding_service = None
        self._anthropic_client = None

    def _get_embedding_service(self):
        """Lazy-load the embedding service."""
        if self._embedding_service is None:
            import sys
            sys.path.insert(0, str(Path(__file__).parent.parent))
            from memory.embeddings import EmbeddingService
            self._embedding_service = EmbeddingService()
        return self._embedding_service

    def _get_anthropic_client(self):
        """Lazy-load the Anthropic client."""
        if self._anthropic_client is None:
            import anthropic
            from config.vault_client import get_api_key
            api_key = get_api_key("anthropic")
            if not api_key:
                raise ValueError("ANTHROPIC_API_KEY not set (checked Vault and environment)")
            self._anthropic_client = anthropic.Anthropic(api_key=api_key)
        return self._anthropic_client

    def search(self, query: str, top_k: Optional[int] = None) -> list[SearchResult]:
        """
        Search for relevant document chunks.

        Args:
            query: Search query
            top_k: Number of results to return (overrides default)

        Returns:
            List of SearchResult objects with chunks and scores
        """
        k = top_k or self.top_k
        embedding_service = self._get_embedding_service()

        # Generate query embedding
        from core.async_utils import run_sync
        query_embedding = run_sync(
            embedding_service.embed(query, preprocess=True)
        )

        # Query ChromaDB
        results = self._collection.query(
            query_embeddings=[query_embedding],
            n_results=k,
            include=["documents", "metadatas", "distances"]
        )

        # Convert to SearchResult objects
        search_results = []
        if results["ids"] and results["ids"][0]:
            for i, chunk_id in enumerate(results["ids"][0]):
                # Convert distance to similarity score (0-1)
                distance = results["distances"][0][i] if results["distances"] else 0
                score = 1.0 / (1.0 + distance)  # Convert distance to similarity

                metadata = results["metadatas"][0][i] if results["metadatas"] else {}
                content = results["documents"][0][i] if results["documents"] else ""

                chunk = DocumentChunk(
                    id=chunk_id,
                    content=content,
                    source_file=metadata.get("source_file", "unknown"),
                    page_number=metadata.get("page_number") if metadata.get("page_number", -1) > 0 else None,
                    chunk_index=metadata.get("chunk_index", 0),
                    doc_type=metadata.get("doc_type", "unknown"),
                )

                search_results.append(SearchResult(chunk=chunk, score=score))

        logger.info(f"Found {len(search_results)} results for query: {query[:50]}...")
        return search_results

    def _format_context(self, results: list[SearchResult]) -> str:
        """
        Format search results as context for Claude.

        Sanitizes each chunk to prevent indirect prompt injection
        via malicious document content.
        """
        if not results:
            return "No relevant documentation found."

        context_parts = []
        for i, result in enumerate(results, 1):
            source = Path(result.chunk.source_file).name
            page_info = f" (page {result.chunk.page_number})" if result.chunk.page_number else ""

            # Sanitize chunk content to prevent indirect prompt injection
            sanitized_content, was_modified = sanitize_context_chunk(
                result.chunk.content,
                source=source
            )
            if was_modified:
                logger.warning(f"Sanitized potentially malicious content from: {source}")

            context_parts.append(
                f"[Source {i}: {source}{page_info}]\n{sanitized_content}\n"
            )

        return "\n".join(context_parts)

    def _format_sources(self, results: list[SearchResult]) -> list[dict]:
        """Format source citations for response."""
        sources = []
        seen_files = set()

        for result in results:
            source_file = result.chunk.source_file
            if source_file not in seen_files:
                seen_files.add(source_file)
                sources.append({
                    "file": Path(source_file).name,
                    "path": source_file,
                    "page": result.chunk.page_number,
                    "score": round(result.score, 3),
                })

        return sources

    def _build_system_prompt(self, permissions: Optional[list] = None) -> str:
        """Build system prompt based on user permissions."""
        base_prompt = self.SYSTEM_PROMPT_WITH_TOOLS

        # Check for admin permissions
        has_config = 'run_config_commands' in (permissions or [])
        has_remediate = 'remediate_interfaces' in (permissions or [])

        if has_config or has_remediate:
            return base_prompt + self.SYSTEM_PROMPT_ADMIN
        else:
            return base_prompt + self.SYSTEM_PROMPT_READONLY

    def generate_response(
        self,
        query: str,
        context_results: Optional[list[SearchResult]] = None,
        model: str = "claude-sonnet-4-20250514",
    ) -> ChatResponse:
        """
        Generate a response using Claude with RAG context.

        Args:
            query: User's question
            context_results: Pre-fetched search results (optional)
            model: Claude model to use

        Returns:
            ChatResponse with answer and sources
        """
        # Get context if not provided
        if context_results is None:
            context_results = self.search(query)

        context = self._format_context(context_results)
        sources = self._format_sources(context_results)

        # Build prompt with XML markers for clear context boundaries
        user_message = f"""<documentation_context>
{context}
</documentation_context>

<user_question>
{query}
</user_question>

Please answer based on the provided documentation context. If the context doesn't contain enough information, say so."""

        try:
            client = self._get_anthropic_client()

            response = client.messages.create(
                model=model,
                max_tokens=1024,
                system=self.SYSTEM_PROMPT,
                messages=[
                    {"role": "user", "content": user_message}
                ]
            )

            answer = response.content[0].text
            logger.info(f"Generated response for: {query[:50]}...")

            # Track token usage
            usage = TokenUsage(
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
                model=model
            )

            return ChatResponse(
                response=answer,
                sources=sources,
                usage=usage
            )

        except Exception as e:
            logger.error(f"Error generating response: {e}")
            return ChatResponse(
                response=f"Error generating response: {str(e)}",
                sources=sources
            )

    def chat(
        self,
        message: str,
        use_tools: bool = True,
        model: str = "claude-sonnet-4-20250514",
        permissions: Optional[list] = None,
        conversation_history: Optional[list] = None
    ) -> ChatResponse:
        """
        Smart chat interface that can use network tools.

        Args:
            message: User's message
            use_tools: Whether to enable network tool calling
            model: Claude model to use (e.g., claude-3-5-haiku-20241022, claude-sonnet-4-20250514)
            permissions: User's permissions (e.g., ['run_config_commands', 'remediate_interfaces'])
            conversation_history: List of previous messages [{"role": "user/assistant", "content": "..."}]

        Returns:
            ChatResponse with answer and sources
        """
        if use_tools:
            return self.generate_response_with_tools(
                message, model=model, permissions=permissions,
                conversation_history=conversation_history
            )
        return self.generate_response(message, model=model)

    def generate_response_with_tools(
        self,
        query: str,
        model: str = "claude-sonnet-4-20250514",
        permissions: Optional[list] = None,
        conversation_history: Optional[list] = None,
    ) -> ChatResponse:
        """
        Generate a response using Claude with both RAG context and network tools.

        This method:
        1. Searches documentation for relevant context
        2. Filters available tools based on user permissions
        3. Calls Claude with permission-appropriate tools
        4. Executes any tool calls Claude requests
        5. Returns combined response with sources

        Args:
            query: User's question
            model: Claude model to use
            permissions: User's permissions for tool access
            conversation_history: Previous messages for multi-turn context

        Returns:
            ChatResponse with answer and sources
        """
        # First, search documentation for context
        context_results = self.search(query)
        doc_context = self._format_context(context_results)
        sources = self._format_sources(context_results)

        # Get tools available for this user's permissions
        available_tools = get_tools_for_permissions(permissions or [])
        system_prompt = self._build_system_prompt(permissions)

        # Build initial message with XML markers for clear context boundaries
        user_message = f"""<documentation_context>
{doc_context}
</documentation_context>

<user_question>
{query}
</user_question>"""

        try:
            client = self._get_anthropic_client()

            # Build messages with conversation history for multi-turn support
            messages = []
            if conversation_history:
                # Add previous conversation turns (limit to last 10 turns to avoid token limits)
                for msg in conversation_history[-20:]:
                    if msg.get("role") in ("user", "assistant") and msg.get("content"):
                        messages.append({"role": msg["role"], "content": msg["content"]})

            # Add current message with context
            messages.append({"role": "user", "content": user_message})

            # Track cumulative token usage across all API calls
            total_input_tokens = 0
            total_output_tokens = 0

            # First call - let Claude decide if it needs tools
            response = client.messages.create(
                model=model,
                max_tokens=2048,
                system=system_prompt,
                tools=available_tools,
                messages=messages
            )

            # Track usage from first call
            total_input_tokens += response.usage.input_tokens
            total_output_tokens += response.usage.output_tokens

            # Process tool calls if any
            tool_results = []
            while response.stop_reason == "tool_use":
                # Extract tool use blocks
                tool_uses = [block for block in response.content if block.type == "tool_use"]

                # Execute each tool
                tool_result_contents = []
                for tool_use in tool_uses:
                    logger.info(f"Executing tool: {tool_use.name} with input: {tool_use.input}")
                    result = execute_tool_sync(tool_use.name, tool_use.input)
                    tool_results.append({
                        "tool": tool_use.name,
                        "input": tool_use.input,
                        "result": result
                    })
                    tool_result_contents.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use.id,
                        "content": str(result)
                    })

                # Add assistant's response and tool results to messages
                messages.append({"role": "assistant", "content": response.content})
                messages.append({"role": "user", "content": tool_result_contents})

                # Continue conversation
                response = client.messages.create(
                    model=model,
                    max_tokens=2048,
                    system=system_prompt,
                    tools=available_tools,
                    messages=messages
                )

                # Track usage from follow-up calls
                total_input_tokens += response.usage.input_tokens
                total_output_tokens += response.usage.output_tokens

            # Extract final text response
            answer_parts = []
            for block in response.content:
                if hasattr(block, "text"):
                    answer_parts.append(block.text)

            answer = "\n".join(answer_parts) if answer_parts else "No response generated."

            # Add tool call info to sources if tools were used
            if tool_results:
                for tr in tool_results:
                    sources.append({
                        "file": f"[Live] {tr['tool']}",
                        "path": "network_tool",
                        "page": None,
                        "score": 1.0,
                        "tool_input": tr["input"]
                    })

            logger.info(f"Generated response with {len(tool_results)} tool calls for: {query[:50]}...")

            # Build cumulative usage
            usage = TokenUsage(
                input_tokens=total_input_tokens,
                output_tokens=total_output_tokens,
                model=model
            )

            return ChatResponse(
                response=answer,
                sources=sources,
                usage=usage
            )

        except Exception as e:
            logger.error(f"Error generating response with tools: {e}")
            # Fall back to simple RAG response
            return self.generate_response(query, context_results)

    def get_stats(self) -> RAGStats:
        """Get statistics about the RAG system."""
        count = self._collection.count()
        return RAGStats(
            document_count=count,
            chunk_count=count,
            collection_name=self.COLLECTION_NAME
        )
