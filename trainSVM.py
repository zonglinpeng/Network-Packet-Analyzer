#Author: Zonglin Peng

import numpy as np
from sklearn.externals import joblib
from sklearn.svm import SVC
import pandas
import random
from sklearn.preprocessing import MinMaxScaler

d = np.load('dataset4.npy')
# d2 = np.load('dataset4.npy')
# d = np.concatenate((d1, d2))
# d =  np.concatenate((d[:600], d[700:]))
random_indices = np.random.permutation(len(d))
d = d[random_indices]

yTr = np.squeeze(np.asarray(d[:, :1])).astype(int)
XTr = np.array(d[:, 1:])

# HALF = int(len(d)/2)
# yTr = np.squeeze(np.asarray(d[:HALF, :1])).astype(int)
# yTe = np.squeeze(np.asarray(d[HALF:, :1])).astype(int)

# XTr = np.array(d[:HALF, 1:])
# XTe = np.array(d[HALF:, 1:])


print("_____________TRAINING_____________")

svc = SVC(gamma='auto', cache_size=7000) # gamma=1,coef0=0,probability=True,
svc.fit(XTr, yTr)

print("_____________PREDICT______________")

print(svc.score(XTr, yTr))
joblib.dump(svc, 'svm3.pkl')

# print("_____________LOAD__________________")
# clf = joblib.load('svm.pkl')
# print(clf.score(XTe, yTe))
