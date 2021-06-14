def nb_classifier():
	import pandas as pd
	
	X_train_data=pd.read_csv("classifier\BN\permission_groups.csv")
	y_train_data=pd.read_csv("classifier\BN\labels.csv")
	X_test_data=pd.read_csv("permissions\permissions_extract.csv")

	import numpy as np
	#共23个权限
	PERMISSION_GROUPS = np.array(
	[
	        ["android.permission.SET_DEBUG_APP"],
	        ["android.permission.READ_PHONE_STATE","android.permission.RECORD_AUDIO","android.permission.INTERNET"],
	        ["android.permission.PROCESS_OUTGOING_CALLS","android.permission.RECORD_AUDIO","android.permission.INTERNET"],
	        
	        ["android.permission.ACCESS_FINE_LOCATION","android.permission.INTERNET","android.permission.RECEIVE_BOOT_COMPLETED"],
	        ["android.permission.ACCESS_COARSE_LOCATION","android.permission.INTERNET","android.permission.RECEIVE_BOOT_COMPLETED"],
	        
	        ["android.permission.RECEIVE_SMS","android.permission.WRITE_SMS"],
	        ["android.permission.SEND_SMS","android.permission.WRITE_SMS"],
	        
	        ["android.permission.INSTALL_SHORTCUT","android.permission.UNINSTALL_SHORTCUT"],
	        ["android.permission.SET_PREFERRED_APPLICATIONS"],
	        
	        
	        #
	        ["android.permission.READ_CALL_LOG","android.permission.INTERNET"],
	        ["android.permission.READ_CONTACTS","android.permission.INTERNET"],
	        ["android.permission.READ_CONTACTS","android.permission.SEND_SMS"],
	        ["android.permission.READ_CALL_LOG","android.permission.SEND_SMS"],
	        
	        ["android.permission.RECEIVE_SMS","android.permission.INTERNET"],
	        ["android.permission.RECEIVE_SMS","android.permission.SEND_SMS"],
	        ["android.permission.READ_SMS","android.permission.INTERNET"],
	        ["android.permission.READ_SMS","android.permission.SEND_SMS"],
	        
	        
	        ["android.permission.ACCESS_FINE_LOCATION","android.permission.SEND_SMS"],
	        ["android.permission.ACCESS_COARSE_LOCATION","android.permission.SEND_SMS"],
	        
	        
	        ["android.permission.READ_LOGS","android.permission.INTERNET"],
	        ["android.permission.READ_LOGS","android.permission.SEND_SMS"],
	        
	        ["android.permission.READ_PROFILE","android.permission.INTERNET"],
	        ["android.permission.READ_PROFILE","android.permission.SEND_SMS"]
	 
	    ]
	)

	#permission_groups 以权限组作为特征 实现降维
	#2行
	row_selected = X_test_data.shape[0]
	#23列
	col_selected = PERMISSION_GROUPS.shape[0]
	#初始化全1新数据2*23
	permission_groups = np.ones([row_selected,col_selected])

	#2行测试样本：
	for i in range(row_selected):
	    #遍历36个权限组
	    for j in range(PERMISSION_GROUPS.shape[0]):
	        #初始化用flag进行标记，所有权限组特征取值都为1
	        flag = 1
	        #遍历权限组中的每个权限
	        for k in range(len(PERMISSION_GROUPS[j])):
	            permission = PERMISSION_GROUPS[j][k]
	            #该组内权限一旦出现取值为0 ，即某个权限不存在，则该组取值标为 0
	            flag = flag * X_test_data[permission][i]
	        permission_groups[i][j] = flag
	                
	permission_groups = pd.DataFrame(permission_groups)

	#更改列索引名称：1-23权限组
	permission_groups.columns = [i for i in range(1,col_selected+1)]

	#要测试的数据变为permission_groups!!!
	#print(permission_groups)

	from sklearn.naive_bayes import BernoulliNB
	# 拟合朴素贝叶斯分类器
	clf = BernoulliNB(alpha=1,binarize=None)
	clf.fit(X_train_data,y_train_data)
	results=clf.predict(permission_groups)
	results=np.array([results])


	return results

