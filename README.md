# URL-Classifier
This code was submitted as part of my 2018 Honours Project for the degree of BEng Digital Security, Forensics & Ethical Hacking. 

## Included
* FeatureExtract.py: Will extract features from a csv file specified in the argument and pull malicious URLs from phishtank. This will all be compiled in to one dataset. 
```
FeatureExtract.py genuine.csv
```
* Spotcheck.ipynb: Jupyter notepad outlining the steps needed to spotcheck four algorithms for effectiveness.
* TrainModel.py: Used to train an ensemble learning model using weightings specified by user. This results in a pickle file to store the trained model.

Syntax:
```
TrainModel.py <LogisticRegression Weight>, <DecisionTree Weight>, <NiaveBayes Weight>, <SVM Weight>
```
Example:
```
TrainModel.py 3,1,2,3
```
* predictor.py: Can be used to make predictions based on previously trained model
```
predictor.py https://www.google.com
```
