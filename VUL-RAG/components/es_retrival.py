#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
from haystack.document_stores import ElasticsearchDocumentStore

try:
    from haystack.nodes import ElasticsearchRetriever
except:
    # In a higher version of farm-haystack, ElasticsearchRetriever does not exist
    from haystack.nodes import BM25Retriever as ElasticsearchRetriever

from common.constant import PreSufConstant
from common.util.data_utils import DataUtils
from common.util.path_util import PathUtil
import common.config as cfg
import logging


from elasticsearch import Elasticsearch
import urllib3
urllib3.disable_warnings()


class ESRetrieval:
    def __init__(self, index_name: str, custom_settings: bool = False):
        if cfg.DISABLE_ES_LOGGING:
            logging.getLogger('elasticsearch').setLevel(logging.CRITICAL)

        self.index = f'{PreSufConstant.DB_NAME_PREFIX_ES.value}{index_name}{PreSufConstant.DB_INDEX_SUFFIX.value}'

        if custom_settings:
            es = Elasticsearch(
                hosts = cfg.ES_CONFIG["host"], 
                port = cfg.ES_CONFIG['port']
            )
            if not es.indices.exists(index = self.index):
                es.indices.create(index = self.index)
            es.indices.put_settings(index = self.index, body = cfg.ES_SETTINGS)

        self.document_store: ElasticsearchDocumentStore = ElasticsearchDocumentStore(
            host = cfg.ES_CONFIG['host'],
            port = cfg.ES_CONFIG['port'],
            scheme = 'http',
            verify_certs = False,
            index = self.index,
        )
        self.retriever: ElasticsearchRetriever = ElasticsearchRetriever(
            document_store = self.document_store
        )

    def write_document(self, documents, batch_size = 512):
        try:
            start_time = time.time()
            self.document_store.write_documents(
                documents = documents,
                index = self.index,
                batch_size = batch_size,
                duplicate_documents = 'skip'
            )
            end_time = time.time()
            logging.info("Write documents finish in %f s." % (end_time - start_time))
        except Exception as e:
            logging.error(f"Error: {e}")

    def __format_retrieved_answers(self, answers):
        formatted_answer_list = []
        for answer in answers:
            formatted_answer_list.append({
                "content": answer.content,
                "cve_id": answer.meta["cve_id"]
            })
        return formatted_answer_list

    def search(self, query, retrieve_top_k = 10):
        """
        Searches for the given query in the specified index and retrieves the top-k results.

        Args:
            query (str): The search query string.
            retrieve_top_k (int, optional): The number of top results to retrieve. Defaults to 10.

        Returns:
            list: A list of formatted retrieved answers. Each answer in the list is a dictionary 
                  containing the following attributes:
                  - 'content' (str): The retrieved document text.
                  - 'cve_id' (str): The CVE ID of the document.
        """
        answers = self.retriever.retrieve(
            query = query, 
            top_k = retrieve_top_k, 
            index = self.index
        )
        return self.__format_retrieved_answers(answers)

class LLM4DetectionRetrieval(ESRetrieval):
    def __init__(self, index_name: str, document_name: str):
        super().__init__(index_name, custom_settings = cfg.ES_USE_CUSTOM_SETTINGS)
        self.retrieval_id = 1
        self.document_name = document_name

    def load_knowledge_documents(self, knowledge_file: str = None):
        if not knowledge_file:
            return []

        vul_knowledge_map = DataUtils.load_json(knowledge_file)
        knowledge_documents = []
        for _, knowledge_list in vul_knowledge_map.items():
            for vul_knowledge_item in knowledge_list:
                try:
                    knowledge_documents.append({
                        "content": vul_knowledge_item[self.document_name],
                        "meta": {
                            "cve_id": vul_knowledge_item['CVE_id']
                        }
                    })
                except Exception as e:
                    logging.error(f"Error: {e}")
        return knowledge_documents


    def update_new_documents(self, doc_path, documents = None):
        if not documents:
            documents = self.load_knowledge_documents(knowledge_file = doc_path)
        if not documents:
            logging.info(f'No documents to update')
            return
        self.write_document(documents)


def test_es_retrieval():
    example_batch_name = "gpt-3.5-turbo_CWE-119_316_pattern_all"
    document_name = "solution"
    doc_path = PathUtil.knowledge_extraction_output(example_batch_name, "json")
    es_retrieval = LLM4DetectionRetrieval(example_batch_name.lower() + "_" + document_name.lower(), document_name)
    es_retrieval.update_new_documents(doc_path = doc_path)
    query = (
        "When removing a device, there may still be work items related to the device "
        "that are either executing or queued for execution."
    )
    answer = es_retrieval.search(query = query)
    print(answer)

if __name__ == '__main__':
    test_es_retrieval()

