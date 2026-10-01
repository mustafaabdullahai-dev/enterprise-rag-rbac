"""Ingestion package: multi-format loading, chunking, classification, indexing."""

from enterprise_rag.ingestion.catalog import CatalogEntry, DocumentCatalog
from enterprise_rag.ingestion.chunker import DocumentChunker
from enterprise_rag.ingestion.classifier import SensitivityClassifier
from enterprise_rag.ingestion.loaders import (
    LoadedDocument,
    LoadedUnit,
    LoaderError,
    load_document,
)
from enterprise_rag.ingestion.pipeline import IngestionPipeline, IngestionReport

__all__ = [
    "CatalogEntry",
    "DocumentCatalog",
    "DocumentChunker",
    "IngestionPipeline",
    "IngestionReport",
    "LoadedDocument",
    "LoadedUnit",
    "LoaderError",
    "SensitivityClassifier",
    "load_document",
]
