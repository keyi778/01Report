# import pandas as pd
# from sklearn.model_selection import train_test_split
# from sklearn.linear_model import LinearRegression
# from sklearn.metrics import mean_squared_error
# from joblib import dump, load
#
# # 加载数据集
# df = pd.read_csv('Traffic_Prediction_Dataset.csv')
#
# # 将数据集分为训练集和测试集
# X = df[['Past_10_sec_traffic']]  # 特征
# y = df['Future_10_sec_traffic']  # 目标变量
#
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
#
# # 创建线性回归模型
# model = LinearRegression()
#
# # 训练模型
# model.fit(X_train, y_train)
#
# # 保存模型到文件
# dump(model, 'linear_regression_model.joblib')
# print('模型已保存.')
#
# # 进行预测
# y_pred = model.predict(X_test)
#
# # 评估模型
# mse = mean_squared_error(y_test, y_pred)
# print(f'均方误差: {mse}')
#
# # 加载模型
# def load_model(filename='linear_regression_model.joblib'):
#     return load(filename)
#
# # 使用模型进行单个预测
# def make_prediction(input_traffic):
#     model = load_model()  # 加载模型
#     # 创建一个DataFrame，其中包含正确的特征名称
#     input_df = pd.DataFrame({'Past_10_sec_traffic': [input_traffic]})
#     prediction = model.predict(input_df)
#     return prediction[0]  # 返回预测结果
#
# # 测试预测函数
# print("对过去10秒流量为30的预测结果是:", make_prediction(30))
# 文件名: prediction_module.py
import pandas as pd
from joblib import load

# 使用加载的模型进行单个预测
def make_prediction(input_traffic):
    # 将输入封装成DataFrame，确保列名与训练时一致
    input_df = pd.DataFrame({'Past_10_sec_traffic': [input_traffic]})
    model = load('linear_regression_model.joblib')
    prediction = model.predict(input_df)
    return prediction[0]
