# -*- coding: utf-8 -*-
import json
import pickle


class DataUtils:
    @staticmethod
    def save_json(path, data):
        with open(path, "w", encoding = "utf-8") as f:
            json.dump(data, f, indent = 4)

    @staticmethod
    def load_json(path):
        with open(path, "r", encoding = "utf-8") as f:
            data = json.load(f)
        return data
    
    @staticmethod
    def load_data_from_pickle_file(path):
        with open(path, 'rb') as file:
            data = pickle.load(file)
        return data
    
    @staticmethod
    def write_data_to_pickle_file(data, path):
        with open(path, 'wb') as file:
            pickle.dump(data, file)
