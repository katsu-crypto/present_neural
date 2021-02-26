from present import * #ここで使用する暗号器を指定する
from Crypto.Random import get_random_bytes#ランダム変数

class Analysis_model():
    def __init__(self,gpu_num,TRAIN_NUM,TEST_NUM,ROUND):
        #変数などの定義
        print("Let's do a Learning----------------!")#Greeting
        self.gpu_num=gpu_num#使用するGPUナンバー
        self.x_train=0#入力トレーニングデータの初期化
        self.x_test=0#入力テストデータの初期化
        self.y_train=0#教師トレーニングデータの初期化
        self.y_test=0#教師テストデータの初期化
        
        self.TRAIN_NUM=TRAIN_NUM#トレーニングデータ数
        self.TEST_NUM=TEST_NUM#テストデータ数
        self.ROUND=ROUND#ラウンド数
        
        #self.x_length=len(self.x_train[0])#トレーニングデータのブロック長
        #self.y_length=len(self.y_train[0])#テストデータのブロック長

        self.learning_rate=0.001#学習率
        self.loss_func='mse'#損失関数

        self.batch_size=200#バッチサイズ
        self.epochsize=300#エポック数
        self.valisplit=0.2#トレーニング・検証データの分割(テストデータの分割ではない)
        
        #アーリーストッピング手法におけるパラメータ
        self.es_monitor='val_loss'#監視するパラメータ
        self.es_patience=10#es_monitorがこの回数以上改善がなかったら，学習を打ち切る
        
        #-----------------------暗号器オブジェクトの作成-------------
        self.cp=CiphMachine(self.ROUND)#暗号器インスタンス
        self.cp.test()#テストを行う

    def data_gen_roundkey(self):
        #-----------------鍵スケジュール解析 入力データ：最終段段鍵--------
        #-----------------データ生成---------------------------------------
        #------------------データをテキストファイルに書き出す---------------
        import os
        path = "./Datas"
        os.makedirs("./Datas", exist_ok=True)#-------結果保存用--------

        file_x_train=open("./Datas/x_train.txt","w")
        file_y_train=open("./Datas/y_train.txt","w")
        file_x_test=open("./Datas/x_test.txt","w")
        file_y_test=open("./Datas/y_test.txt","w")

        SUM=self.TRAIN_NUM+self.TEST_NUM
        for i in range(SUM): 
            cp=CiphMachine(self.ROUND)
            round_key=cp.last_round_key#段鍵
            mas_key=cp.mas_key#秘密鍵

            if(i<self.TRAIN_NUM):
                for j in range(cp.key_len):
                    file_y_train.write(str((mas_key>>j)&1))
                    file_y_train.write(" ")    
                file_y_train.write("\n")
                for j in range(cp.block_len):
                    file_x_train.write(str((round_key>>j)&1))
                    file_x_train.write(" ")  
                file_x_train.write("\n")
            else:
                for j in range(cp.key_len):
                    file_y_test.write(str((mas_key>>j)&1))
                    file_y_test.write(" ")    
                file_y_test.write("\n")
                for j in range(cp.block_len):
                    file_x_test.write(str((round_key>>j)&1))
                    file_x_test.write(" ")  
                file_x_test.write("\n")

        file_x_train.close()
        file_y_train.close()
        file_x_test.close()
        file_y_test.close()
        print("Completed Data_Generating")#データの生成完了メッセージ
        
        #---------------------データの配列への変換------------------------
        import numpy as np
        self.x_train=np.loadtxt("./Datas/x_train.txt")
        self.y_train=np.loadtxt("./Datas/y_train.txt")
        self.x_test=np.loadtxt("./Datas/x_test.txt")
        self.y_test=np.loadtxt("./Datas/y_test.txt")
        print("Completed Data_Trainslation")#リストへの変換の完了メッセージ

    def data_gen_keyreg(self):
        #-----------------鍵スケジュール解析 入力データ：最終段鍵スケジュール内部状態 --------
        #-----------------データ生成---------------------------------------
        #------------------データをテキストファイルに書き出す---------------
        import os
        path = "./Datas"
        os.makedirs("./Datas", exist_ok=True)#-------結果保存用--------

        file_x_train=open("./Datas/x_train.txt","w")
        file_y_train=open("./Datas/y_train.txt","w")
        file_x_test=open("./Datas/x_test.txt","w")
        file_y_test=open("./Datas/y_test.txt","w")

        SUM=self.TRAIN_NUM+self.TEST_NUM
        for i in range(SUM): 
            cp=CiphMachine(self.ROUND)
            key_reg=cp.last_round_key_reg#キーレジスタ
            mas_key=cp.mas_key#秘密鍵

            if(i<self.TRAIN_NUM):
                for j in range(cp.key_len):
                    file_y_train.write(str((mas_key>>j)&1))
                    file_y_train.write(" ")    
                file_y_train.write("\n")
                for j in range(cp.key_len):
                    file_x_train.write(str((key_reg>>j)&1))
                    file_x_train.write(" ")  
                file_x_train.write("\n")
            else:
                for j in range(cp.key_len):
                    file_y_test.write(str((mas_key>>j)&1))
                    file_y_test.write(" ")    
                file_y_test.write("\n")
                for j in range(cp.key_len):
                    file_x_test.write(str((key_reg>>j)&1))
                    file_x_test.write(" ")  
                file_x_test.write("\n")

        file_x_train.close()
        file_y_train.close()
        file_x_test.close()
        file_y_test.close()
        print("Completed Data_Generating")#データの生成完了メッセージ
        
        #---------------------データの配列への変換------------------------
        import numpy as np
        self.x_train=np.loadtxt("./Datas/x_train.txt")
        self.y_train=np.loadtxt("./Datas/y_train.txt")
        self.x_test=np.loadtxt("./Datas/x_test.txt")
        self.y_test=np.loadtxt("./Datas/y_test.txt")
        print("Completed Data_Trainslation")#リストへの変換の完了メッセージ
        
    def learning(self):
        #鍵スケジュール解析の学習モデル＆実行
        import numpy as np
        x_train=self.x_train
        y_train=self.y_train
        x_test=self.x_test
        y_test=self.y_test
        
        acc_list=[]#正答率を格納するリスト
        
        print("Model for predicting Plain text.")#Greeting
        
        #-----------------------使用するGPU指定------------------------
        import os
        import tensorflow as tf
        # Specify which GPU(s) to use
        os.environ["CUDA_VISIBLE_DEVICES"] = self.gpu_num  # Or 2, 3, etc. other than 0

        # On CPU/GPU placement
        config = tf.compat.v1.ConfigProto(allow_soft_placement=True, log_device_placement=True)
        config.gpu_options.allow_growth = True
        tf.compat.v1.Session(config=config)
        # Note that ConfigProto disappeared in TF-2.0
        
        for bit_posi in range(len(y_train[0])):
            #各ビットごとに正答率を求める
            #y_trainのbit_posi列だけを抜き出す
            y_train_column=y_train.T[bit_posi]
            y_test_column=y_test.T[bit_posi]
            
            for trial in range(10):
                #学習が成功するまで学習を繰り返す ただし上限あり (失敗は val_acc ≒ 0.5 とする)
                #----------------------モデル作成-----------------------
                from tensorflow import keras
                model = keras.Sequential()

                #中間層の追加
                from tensorflow.python.keras.layers import Dense

                model.add(
                    Dense(
                        units=32,#パーセプトロン数
                        input_shape=(len(x_train[0]) ,),#入力層だけ入力のパーセプトロン数を指定
                        activation="relu",#活性化関数
                        kernel_initializer=keras.initializers.RandomNormal(mean=0.0, stddev=0.05, seed=None)#パラメータ初期化
                    )
                )
                model.add(
                    Dense(
                        units=16,#パーセプトロン数
                        activation="relu",#活性化関数
                        kernel_initializer=keras.initializers.RandomNormal(mean=0.0, stddev=0.05, seed=None)#パラメータ初期化
                    )
                )
                model.add(
                    Dense(
                        units=8,#パーセプトロン数
                        activation="relu",#活性化関数
                        kernel_initializer=keras.initializers.RandomNormal(mean=0.0, stddev=0.05, seed=None)#パラメータ初期化
                    )
                )
                #出力層の追加
                model.add(
                    Dense(
                        units=1,#パーセプトロン数
                        #活性化関数なし
                        kernel_initializer=keras.initializers.RandomNormal(mean=0.0, stddev=0.05, seed=None)#パラメータ初期化
                    )
                )

                #---------------------------------学習-------------------------------
                # Early-stopping 
                early_stopping = keras.callbacks.EarlyStopping(monitor=self.es_monitor, min_delta=0, patience=self.es_patience, verbose=0, mode='auto')#この形式で書かないと怒られる

                #オプティマイザー(最適化関数)の指定
                opt = keras.optimizers.Adam(
                    learning_rate=self.learning_rate#学習率の指定
                )

                #モデルのコンパイル
                model.compile(
                    optimizer=opt,#上記の最適化関数
                    loss=self.loss_func,#損失関数
                    metrics=['accuracy']
                )

                #計算開始
                history_adam=model.fit(
                    x_train,
                    y_train_column,
                    batch_size=self.batch_size,
                    epochs=self.epochsize,
                    validation_split=self.valisplit,
                    callbacks=[early_stopping]#アーリーストッピング
                )


                #---------------------------------------テストフェーズ---------------------
                #テストフェーズ時の予測値
                predict=model.predict(x_test)#予測値は0～1の実数で表現される
                predict=(predict>0.5)*1#それを0or1で表現する
                answer=(predict.T==y_test_column)*1#教師データy_testと答え合わせ 正解なら1 不正解なら0
                #正答率 
                acc=np.sum(answer)/(self.TEST_NUM)

                loss_value = history_adam.history["val_loss"][len(history_adam.history["val_loss"]) -1]#val_lossの最終値
                if(loss_value<0.45):#学習が成功したならば 
                    print("end of %dth bit learning" %  bit_posi)
                    print("Accuracy is below")
                    #print(acc)#リストで表示
                    print(acc)
                    print("")#ただの改行
                    acc_list.append(acc)
                    break
                else:
                    if(trial<9):
                        print("Failure of Learning, Start of Re_Learning")
        
        #各ビットの正答率の平均
        print("Accuracy is below")
        #print(acc_list)#リストで表示
        for acc_i in acc_list:
            print(str(acc_i)+",",end="")#リストaccの要素をカンマを付けながら表示
        print("\n")
        
        #正答率の平均
        print("Average Accuracy is below")
        print(sum(acc_list)/len(acc_list))
        print("")