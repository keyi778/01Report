# import pandas as pd
# from joblib import load
# from sklearn.metrics import accuracy_score, classification_report
#
# def load_and_preprocess(data_path):
#     df = pd.read_csv(data_path)
#     df.columns = df.columns.str.strip()
#     df['Label'] = df['Label'].astype('category')
#     return df
#
# def predict_and_accumulate_scores(models, data):
#     # 初始化得分字典，其中每个类别对应的得分初始为0
#     scores = pd.DataFrame(0, index=data.index, columns=['Benign', 'Infilteration', 'Bot', 'DDOS attack-HOIC'])
#
#     # 遍历所有模型和它们的得分规则
#     for model_path, score_rules in models.items():
#         model = load(model_path)
#         predictions = model.predict(data.drop('Label', axis=1))
#
#         # 应用得分规则，更新得分表
#         for i, pred in enumerate(predictions):
#             if pred in score_rules:
#                 for label, score in score_rules[pred].items():
#                     scores.loc[i, label] += score
#
#     # 最高分作为最终预测结果
#     data['Predicted_Label'] = scores.idxmax(axis=1)
#     return data
#
# def main():
#     data_path = 'test.csv'  # 数据文件路径
#     data = load_and_preprocess(data_path)
#
#     # 模型及其得分规则
#     models = {
#         'InfilterationMaster.joblib': {0: {'Benign': 8}, 1: {'Infilteration': 16}},
#         'BotMaster.joblib': {0: {'Benign': 8}, 1: {'Bot': 24}},
#         'DDOS attack-HOICMaster.joblib': {0: {'Benign': 8}, 1: {'DDOS attack-HOIC': 24}},
#         'ComprehensiveMaster.joblib': {0: {'Benign': 4}, 1: {'Infilteration': 4}, 2: {'Bot': 4}, 3: {'DDOS attack-HOIC': 4}}
#     }
#
#     final_data = predict_and_accumulate_scores(models, data)
#
#     print("Final Predictions:")
#     print(final_data[['Label', 'Predicted_Label']].head())
#
#     # 可选：保存结果
#     final_data.to_csv('final_predictions.csv', index=False)
#
# if __name__ == "__main__":
#     main()




# import pandas as pd
# from joblib import load
#
# def load_and_preprocess(data_path):
#     df = pd.read_csv(data_path)
#     df.columns = df.columns.str.strip()
#     df['Label'] = df['Label'].astype('category')
#     return df
#
# def predict_and_accumulate_scores(models, data):
#     scores = pd.DataFrame(0, index=data.index, columns=['Benign', 'Infilteration', 'Bot', 'DDOS attack-HOIC'])
#     for model_path, score_rules in models.items():
#         model = load(model_path)
#         predictions = model.predict(data.drop('Label', axis=1))
#         for i, pred in enumerate(predictions):
#             if pred in score_rules:
#                 for label, score in score_rules[pred].items():
#                     scores.loc[i, label] += score
#     data['Predicted_Label'] = scores.idxmax(axis=1)
#     return data
#
# def apply_models(data_path, output_csv):
#     data = load_and_preprocess(data_path)
#     models = {
#         'InfilterationMaster.joblib': {0: {'Benign': 8}, 1: {'Infilteration': 16}},
#         'BotMaster.joblib': {0: {'Benign': 8}, 1: {'Bot': 24}},
#         'DDOS attack-HOICMaster.joblib': {0: {'Benign': 8}, 1: {'DDOS attack-HOIC': 24}},
#         'ComprehensiveMaster.joblib': {0: {'Benign': 4}, 1: {'Infilteration': 4}, 2: {'Bot': 4}, 3: {'DDOS attack-HOIC': 4}}
#     }
#     final_data = predict_and_accumulate_scores(models, data)
#     final_data.to_csv(output_csv, index=False)
#     return final_data
#
# apply_models('test.csv', 'final.csv')



import pandas as pd
from joblib import load

def predict_single_record(dst_port, protocol, fwd_pkt_len_max, fwd_pkt_len_min,
                          fwd_pkt_len_mean, fwd_pkt_len_std, bwd_pkt_len_max,
                          bwd_pkt_len_min, bwd_pkt_len_mean, bwd_pkt_len_std,
                          fin_flag_cnt, syn_flag_cnt, rst_flag_cnt, psh_flag_cnt,
                          ack_flag_cnt, urg_flag_cnt, cwe_flag_count, ece_flag_cnt):
    # 构建单行DataFrame
    data = pd.DataFrame({
        'Dst Port': [dst_port],
        'Protocol': [protocol],
        'Fwd Pkt Len Max': [fwd_pkt_len_max],
        'Fwd Pkt Len Min': [fwd_pkt_len_min],
        'Fwd Pkt Len Mean': [fwd_pkt_len_mean],
        'Fwd Pkt Len Std': [fwd_pkt_len_std],
        'Bwd Pkt Len Max': [bwd_pkt_len_max],
        'Bwd Pkt Len Min': [bwd_pkt_len_min],
        'Bwd Pkt Len Mean': [bwd_pkt_len_mean],
        'Bwd Pkt Len Std': [bwd_pkt_len_std],
        'FIN Flag Cnt': [fin_flag_cnt],
        'SYN Flag Cnt': [syn_flag_cnt],
        'RST Flag Cnt': [rst_flag_cnt],
        'PSH Flag Cnt': [psh_flag_cnt],
        'ACK Flag Cnt': [ack_flag_cnt],
        'URG Flag Cnt': [urg_flag_cnt],
        'CWE Flag Count': [cwe_flag_count],
        'ECE Flag Cnt': [ece_flag_cnt]
    })

    # 定义模型路径和得分规则
    models = {
        'InfilterationMaster.joblib': {0: {'Benign': 8}, 1: {'Infilteration': 21}},
        'BotMaster.joblib': {0: {'Benign': 8}, 1: {'Bot': 24}},
        'DDOS attack-HOICMaster.joblib': {0: {'Benign': 8}, 1: {'DDOS attack-HOIC': 24}},
        'ComprehensiveMaster.joblib': {0: {'Benign': 4}, 1: {'Infilteration': 4}, 2: {'Bot': 4}, 3: {'DDOS attack-HOIC': 4}}
    }

    # 初始化得分
    scores = pd.Series(0, index=['Benign', 'Infilteration', 'Bot', 'DDOS attack-HOIC'])

    # 加载模型并预测
    for model_path, score_rules in models.items():
        model = load(model_path)
        prediction = model.predict(data)[0]
        for outcome, points in score_rules[prediction].items():
            scores[outcome] += points

    # 返回得分最高的预测
    return scores.idxmax()
