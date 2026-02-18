"""
Embedding service for semantic search.

Uses sentence-transformers for local embedding generation.
"""

import asyncio
from typing import Optional


class EmbeddingService:
    """
    Generate embeddings for semantic search.

    Uses sentence-transformers all-MiniLM-L6-v2 model by default.
    Optimized for speed (~15ms per embedding) while maintaining quality.
    """

    # Network domain abbreviation expansions
    ABBREVIATIONS = {
        "OSPF": "Open Shortest Path First routing protocol",
        "BGP": "Border Gateway Protocol",
        "NHRP": "Next Hop Resolution Protocol",
        "DMVPN": "Dynamic Multipoint VPN",
        "EIGRP": "Enhanced Interior Gateway Routing Protocol",
        "VRF": "Virtual Routing and Forwarding",
        "VLAN": "Virtual LAN",
        "SVI": "Switch Virtual Interface",
        "ACL": "Access Control List",
        "NAT": "Network Address Translation",
        "GRE": "Generic Routing Encapsulation",
        "IPsec": "Internet Protocol Security",
        "IKE": "Internet Key Exchange",
        "MTU": "Maximum Transmission Unit",
        "QoS": "Quality of Service",
        "CDP": "Cisco Discovery Protocol",
        "LLDP": "Link Layer Discovery Protocol",
        "SNMP": "Simple Network Management Protocol",
        "NTP": "Network Time Protocol",
        "AAA": "Authentication Authorization Accounting",
        "TACACS": "Terminal Access Controller Access-Control System",
        "SSH": "Secure Shell",
        "MDT": "Model-Driven Telemetry",
        "NETCONF": "Network Configuration Protocol",
        "YANG": "Yet Another Next Generation data modeling",
    }

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        """
        Initialize embedding service.

        Args:
            model_name: sentence-transformers model to use
        """
        self.model_name = model_name
        self._model = None

    def _get_model(self):
        """Lazy-load the embedding model."""
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                # Try loading from cache first to avoid HuggingFace API calls
                # This prevents 404 errors for missing optional files (additional_chat_templates)
                try:
                    self._model = SentenceTransformer(
                        self.model_name,
                        local_files_only=True
                    )
                except Exception:
                    # Fall back to network download if not cached
                    self._model = SentenceTransformer(self.model_name)
            except ImportError:
                raise ImportError(
                    "sentence-transformers is required for semantic search. "
                    "Install with: pip install sentence-transformers"
                )
        return self._model

    def preprocess(self, text: str) -> str:
        """
        Preprocess text for embedding.

        Expands network domain abbreviations for better semantic matching.
        """
        processed = text
        for abbr, expansion in self.ABBREVIATIONS.items():
            # Only expand if it appears as a word boundary
            processed = processed.replace(f" {abbr} ", f" {expansion} ")
            processed = processed.replace(f" {abbr}.", f" {expansion}.")
            processed = processed.replace(f" {abbr},", f" {expansion},")
            if processed.startswith(f"{abbr} "):
                processed = f"{expansion} " + processed[len(abbr) + 1:]
        return processed

    async def embed(self, text: str, preprocess: bool = True) -> list[float]:
        """
        Generate embedding for text.

        Args:
            text: Text to embed
            preprocess: Whether to expand abbreviations

        Returns:
            List of floats representing the embedding vector
        """
        if preprocess:
            text = self.preprocess(text)

        model = self._get_model()

        # Run in thread pool to avoid blocking
        embedding = await asyncio.to_thread(
            model.encode,
            text,
            convert_to_numpy=True
        )

        return embedding.tolist()

    async def embed_batch(
        self,
        texts: list[str],
        preprocess: bool = True
    ) -> list[list[float]]:
        """
        Generate embeddings for multiple texts.

        More efficient than calling embed() repeatedly.
        """
        if preprocess:
            texts = [self.preprocess(t) for t in texts]

        model = self._get_model()

        embeddings = await asyncio.to_thread(
            model.encode,
            texts,
            convert_to_numpy=True
        )

        return [e.tolist() for e in embeddings]

    def embedding_dimension(self) -> int:
        """Get the dimension of embeddings from this model."""
        model = self._get_model()
        return model.get_sentence_embedding_dimension()
