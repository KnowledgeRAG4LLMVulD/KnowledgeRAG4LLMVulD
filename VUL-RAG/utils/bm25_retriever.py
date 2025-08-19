import spacy
from rank_bm25 import BM25Okapi

# Load spaCy model (e.g., English model "en_core_web_sm")
# If not installed, run: pip install spacy && python -m spacy download en_core_web_sm
nlp = spacy.load("en_core_web_sm")

class BM25Retriever:
    def __init__(self):
        self.bm25 = None
        self.corpus = None

    def _tokenize(self, text):
        """Tokenize using a method similar to Elasticsearch's standard tokenizer
        Split by spaces and punctuation, no stemming
        """
        doc = nlp(text)
        tokens = [token.text.lower() for token in doc if not token.is_punct]
        return tokens

    def set_corpus(self, corpus):
        """
        Set and process the corpus for subsequent searches.
        corpus: List of documents (strings)
        """
        self.corpus = corpus
        tokenized_corpus = [self._tokenize(doc) for doc in self.corpus]
        self.bm25 = BM25Okapi(tokenized_corpus)

    def search(self, query, top_n=-1):
        """
        Perform BM25 retrieval using the preset corpus.
        query: Query string
        top_n: Return top_n results; if top_n = -1, return all documents sorted
        return: List of indices sorted by score in descending order
        """
        if self.bm25 is None:
            raise ValueError("Corpus has not been set. Please call set_corpus() first.")

        tokenized_query = self._tokenize(query)
        scores = self.bm25.get_scores(tokenized_query)

        sorted_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
        return sorted_indices if top_n == -1 else sorted_indices[:top_n]

if __name__ == "__main__":
    corpus = [
        "This is a test document.",
        "Another document for BM25.",
        "BM25 is a ranking function."
    ]
    query = "BM25 ranking"

    # Use the new BM25Retriever class
    retriever = BM25Retriever()
    retriever.set_corpus(corpus)

    all_sorted_indices = retriever.search(query, top_n=-1)
    print("Sorted order of all documents:")
    for idx in all_sorted_indices:
        print(f"Index: {idx}, Document: {corpus[idx]}")
    
    top2_indices = retriever.search(query, top_n=2)
    print("Sorted order of top 2 documents:")
    for idx in top2_indices:
        print(f"Index: {idx}, Document: {corpus[idx]}")