#!/usr/bin/python3
#从 flask 模块中引入 request 对象，request 对象中的属性 files 记录了上传文件的相关信息
#从 flask 模块中引入函数 send_from_directory，该函数用于实现下载文件
from flask import Flask, render_template, request, send_from_directory
import os
import pandas as pd

app = Flask(__name__)

@app.route('/')
def index():
	#设置访问路径 / 时，使用函数 index 进行处理，函数 index 列出目录 upload 下所有的文件名，作为参数传给首页的模板 index.html
	#在首页 index.html 中根据 entries 显示每个文件的下载链接。
    entries = os.listdir('./upload')
    return render_template('index.html', entries = entries)

#设置访问路径 /upload 时，使用函数 upload 进行处理。
#函数 upload 从 request 对象中获取上传的文件信息，request.files 是一个字典，使用表单中的文件字段名作为索引。
@app.route('/upload', methods=['POST'])
def upload():
    f = request.files['file']
    #设置保存路径
    path = os.path.join('./upload', f.filename)
    #保存文件
    f.save(path)
    #跳转至上传成功界面
    return render_template('upload.html')

#每个文件都有一个下载链接，形式为 /files/ 文件名，假如文件名为 test.txt，则下载链接为 /files/test.txt。
@app.route('/files/<filename>')
#函数 files 调用 send_from_directory 将 upload 目录下的文件发送给客户，as_attachment=True 表示文件作为附件下载
def files(filename):
    return send_from_directory('./upload', filename, as_attachment=True)


#响应检测按键
@app.route('/check')
def check():
    #print("before extract")
    extract()
    
    #获取权限
    results=get_results()
    #获取文件名
    apk_name_list=get_apk_name_list()

    #print(apk_name_list)
    return render_template('details.html',results=results,apk_name_list=apk_name_list)

def get_apk_name_list():
    #注意中文编码的问题
    apk_name_list = pd.read_csv('permissions/apk_name_list.csv',encoding='gbk')
    apk_name_list=apk_name_list.columns.values
    return apk_name_list


#用3种模型进行检测并返回结果
def get_results():
    import sys
    import numpy as np
    sys.path.append(r'classifier/knn')
    sys.path.append(r'classifier/BN')
    sys.path.append(r'classifier/dt')
    '''python import模块时， 是在sys.path里按顺序查找的。
    sys.path是一个列表，里面以字符串的形式存储了许多路径。
    使用A.py文件中的函数需要先将他的文件路径放到sys.path中'''

    #1
    import knn
    results_knn=knn.knn_classifier()

    #2
    import nb
    results_nb=nb.nb_classifier()

    #3
    import dt
    results_dt=dt.dt_classifier()

    results=np.append(results_knn,results_nb,axis=0)
    results=np.append(results,results_nb,axis=0)
    
    # print(results_knn)
    # print(results_nb)
    # print(results_dt)
    results=results.T
    print(results)
    return results

    # results=[]
    # results.append(results_knn)
    # results.append(results_nb)
    # results.append(results_dt)


    # results=np.array(results)

    # row=len(results)
    # col=len(results[0])
    # results_new=np.array((row,col))
    # for i in range(row):
    #     for j in range(col):
    #         if results[i][j]==1:
    #             results_new[i][j]="Malware"
    #         else: results_new[i][j]="Begin"


#提取权限，得到csv矩阵
def extract():
    #coding:utf-8
    '''
    simple demo of extracting apk permission list
    the result will be saved in the "permission_list.csv"
    please put all apk file in the "source_apk" folder
    '''
    from androguard.core.bytecodes.apk import APK
    import os
    import pandas as pd
    import numpy as np

    #input:apk文件所在目录
    #output：apk文件名列表
    def file_name(file_dir):
        file_list = []
        for root, dirs, files in os.walk(file_dir):
            file_list.append(files)
        return file_list[0]

    #找到权限字典163维度模板：
    permissions = pd.read_csv('permissions\permissions_extract0.csv')
    permissions_columns=permissions.columns.values

    #print(permissions)

    # PERMISSIONS_NAME = permissions_extract.columns.values
    # #163维度零向量
    # VECTOR_ZERO=np.zeros(len(PERMISSIONS_NAME))
    
    #permissions_public_index=np.intersect1d(PERMISSIONS_NAME,)
    #


    #遍历upload文件夹
    file_list = file_name('upload')
    print('processing...')

    #apk——name记录文件
    f_apk_name = open('permissions/apk_name_list.csv','w')
    #记录apk文件总个数，一个写入一行
    apk_counter=0
    for apk in file_list:
        #添加全0行
        permissions.loc[apk_counter] = 0
        print(apk_counter,"finish")
        #得到apk文件路径
        apk_path = APK('upload/' + apk)
        #得到每个apk文件的权限list
        permissions_ofapk = apk_path.get_permissions()
        
        # permissions_ofapk=np.array(permissions_ofapk)
        # print(type(permissions_ofapk))
        # print(permissions_ofapk)
        
        #遍历apk文件的声明权限列表，若在模板中有，则写为1，否则默认为0
        for permission_index in permissions_ofapk:
            if permission_index in permissions_columns:
                permissions.loc[apk_counter,permission_index]=1

        #apk名称写入文件
        f_apk_name.write(apk+',')
        apk_counter=apk_counter+1


    #程序正确，人工检测一遍！！！！！！！！！！！！
    permissions.to_csv('permissions\permissions_extract.csv',index=False)

    #print(permissions)
    #     permissions.to_csv('permissions\permissions_extract.csv',index=Flask)

        #print(type(b))
        # print(b)
        # b=pd.DataFrame(b)
        # b.to_csv("aaa.csv")

        # #寻找公共权限
        # permissions_public_index=np.intersect1d(PERMISSIONS_NAME,b)
        # permissions_public[permissions_public_index]=1
        # #permission_public写入一行
        # #numpy转为dataframe格式
        # permissions_public = pd.DataFrame(permissions_public)
        # print(permissions_public)
        # print("bbbb")
        # permissions_public.to_csv("aaa.csv")
    print('finish_extract!')
    

app.jinja_env.auto_reload = True
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.run(debug = True)

