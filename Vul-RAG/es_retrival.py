# !/usr/bin/env python
# -*- coding: utf-8 -*-
import time
from haystack.document_stores import ElasticsearchDocumentStore
from haystack.nodes import ElasticsearchRetriever
from util.constant_util import PreSufConstant
from util.file_util import FileUtil
from util.path_util import PathUtil

import pdb
import urllib3
from elasticsearch import RequestsHttpConnection
urllib3.disable_warnings()

es_config = {
    "host": "",
    "port": 9200,
    "username": "",
    "password": ""
}


class ESRetrieval:
    def __init__(self, index_name):
        self.index = f'{PreSufConstant.DB_NAME_PREFIX_ES}{index_name}{PreSufConstant.DB_INDEX_SUFFIX}'
        self.document_store: ElasticsearchDocumentStore = ElasticsearchDocumentStore(
            host=es_config['host'],
            port=es_config['port'],
            username=es_config['username'],
            password=es_config['password'],
            scheme='http',
            verify_certs=False,
            index=self.index,
        )
        self.retriever: ElasticsearchRetriever = ElasticsearchRetriever(
            document_store=self.document_store
        )

    def write_document(self, documents, batch_size=500):
        try:
            start_time = time.time()
            self.document_store.write_documents(
                documents=documents,
                index=self.index,
                batch_size=batch_size,
                duplicate_documents='skip'
            )
            end_time = time.time()
            print("Write documents finish in %f s." % (end_time - start_time))
        except BaseException as e:
            print(e)

    def search(self, query, retrieve_top_k=10):
        answer = self.retriever.retrieve(query=query, top_k=retrieve_top_k, index=self.index)
        return self.get_answer(answer)

    def get_retriever(self):
        return self.retriever

    def format_answer(self, answer_item):
        answer_dict = {}
        answer_dict["content"] = answer_item.content
        answer_dict["cve_id"] = str(answer_item.meta["cve_id"])
        return answer_dict

    def get_answer(self, answer):
        result_list = []
        for item in answer:
            result_list.append(self.format_answer(item))
        return result_list

    @staticmethod
    def load_documents():
        return []


class LLM4DetectionRetrieval(ESRetrieval):
    def __init__(self, index_name, document_name):
        index_name = index_name
        super().__init__(index_name)
        self.retrieval_id = 1
        self.document_name = document_name

    def load_documents(self, file_path=None):

        if not file_path:
            return []

        vul_knowledge_list = FileUtil.load_data_list_from_json_file(file_path)

        documents = []
        for vul_knowledge_item in vul_knowledge_list:
            # pdb.set_trace()
            for vul_knowledge in vul_knowledge_list[vul_knowledge_item]:
                # pdb.set_trace()
                try:
                    documents.append({
                        "content": vul_knowledge[self.document_name],
                        "meta": {
                            "cve_id": vul_knowledge['CVE_id']
                        }
                    })
                except Exception as e:
                    print(e)
        return documents


    def update_new_document(self, doc_path, documents=None):
        if not documents:
            documents = self.load_documents(file_path=doc_path)
        if not documents:
            print(f'nothing should be updated')
            return
        self.write_document(documents)
        # self.update_embedding()


if __name__ == '__main__':

    example_batch_name = "gpt-3.5-turbo_CWE-416_pattern"
    document_name = "solution"
    doc_path = PathUtil.knowledge_extraction_output(example_batch_name, "json")
    es_retrieval = LLM4DetectionRetrieval(example_batch_name.lower() + "_" + document_name.lower(), document_name)
    es_retrieval.update_new_document(doc_path=doc_path)
    query = "When removing a device, there may still be work items related to the device that are either executing or queued for execution."
    answer = es_retrieval.search(query=query)
    print(answer)
