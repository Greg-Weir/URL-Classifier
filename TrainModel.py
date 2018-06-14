import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import VotingClassifier
from sklearn.externals import joblib
import sys

weight1 = sys.argv[1]
weight2 = sys.argv[2]
weight3 = sys.argv[3]
weight4 = sys.argv[4]

urls = 'urls.csv'
data_train = pd.read_csv(urls)
feature_cols = ['url len', 'domain len', 'is IP', 'dot count', 'symbol count',
                'symbol count_tld', 'keywords', 'keywords_tld', 'count @', 'is redirect']
X = data_train.loc[:, feature_cols]
y = data_train.classification

logreg = LogisticRegression()
svm_pred = SVC(probability=True)
tree = DecisionTreeClassifier()
nb = GaussianNB()
join = VotingClassifier(estimators=[('LR', logreg), ('Tree', tree),
                        ('NB', nb), ('SVM', svm_pred)], voting='soft', weights=[weight1, weight2,
                                                                                weight3, weight4])
join.fit(X, y)

# Export trained model
joblib.dump(join, 'model.pk1')
