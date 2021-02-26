from block_ciph import *
from Crypto.Random import get_random_bytes#ランダム変数

class CiphMachine(Block_ciph):
    #暗号器のクラスCiphMachine
    #ブロック暗号向けの演算をまとめたBlock_ciphクラスを継承
    #秘密鍵はインスタンス生成時にランダムに設定
    
    def __init__(self,ROUND):
        #変数の定義など
        
        #------------------------------変更する必要のある変数-----------------------------------
        self.full_round=31#段数(フルラウンド)
        self.block_len=64#ブロック長
        self.key_len=80#秘密鍵長
        self.sbox=[0xC,0x5,0x6,0xB,0x9,0x0,0xA,0xD,0x3,0xE,0xF,0x8,0x4,0x7,0x1,0x2]#S-Box
        self.perm=[0,16,32,48,1,17,33,49,2,18,34,50,3,19,35,51,
                4,20,36,52,5,21,37,53,6,22,38,54,7,23,39,55,
                8,24,40,56,9,25,41,57,10,26,42,58,11,27,43,59,
                12,28,44,60,13,29,45,61,14,30,46,62,15,31,47,63]#1ビット転置
        
        #テストベクトルのデータ,秘密鍵，平文，暗号文の順番はそろえること
        self.test_mas_key=[0x00000000000000000000,0xFFFFFFFFFFFFFFFFFFFF
                           ,0x00000000000000000000,0xFFFFFFFFFFFFFFFFFFFF]#テストベクトルの秘密鍵
        self.test_plain=[0x0000000000000000,0x0000000000000000
                         ,0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF]#テストベクトルの平文
        self.test_vector=[0x5579C1387B228445,0xE72C46C0F5945049
                          ,0xA112FFC72F68417B,0x3333DCD3213210D2]#テストベクトルの暗号文
        #---------------------------(終)変更する必要のある変数-----------------------------------
        
        self.ROUND=ROUND#段数(フルではない)
        self.mas_key=int.from_bytes(get_random_bytes(int(self.key_len/8)),byteorder='big')#秘密鍵をランダムに設定
        self.round_key, self.round_key_reg = self.key_sch(self.mas_key,self.ROUND)#段鍵が保存されている配列
        self.last_round_key=self.round_key[ len(self.round_key)-1 ]#最終段段鍵
        self.last_round_key_reg=self.round_key_reg[ len(self.round_key)-1 ]#最終段キーレジスタ

    def key_sch(self,key,ROUND):
        #鍵スケジュールのモジュール
        #【引数】秘密鍵, 段数
        #【戻り値】段鍵が格納されたリスト，最終段鍵スケジュール内部状態 の2つ
        round_key=[]#各段の段鍵を格納する配列
        round_key_reg=[]#各段の鍵スケジュール内部状態を格納する配列
        #print(len(sbox))
        reg=key#鍵スケジュール内部状態(キーレジスタ)に秘密鍵を代入
        for r in range(ROUND):
            #print( format(reg , "080b"))
            round_key.append( self.extract(reg,79,16) )#79～16bitを段鍵として抽出,配列round_keyに追加
            round_key_reg.append( reg )#鍵スケジュール内部状態80ビットを配列round_key_regに追加
            reg=self.rotate_left_shift(reg,61,self.key_len)#61bit left rotate
            reg=self.s_apply(reg,self.sbox,76,self.key_len)#76～79ビット目にs-boxを適用
            reg=self.round_count(reg,r+1,15,self.key_len)#15～19ビット目に段定数をXOR
        round_key.append( self.extract(reg,79,16) )#繰り返し後，79～16bitを段鍵として抽出して配列round_keyに追加
        round_key_reg.append( reg )#繰り返し後，鍵スケジュール内部状態80ビットを配列round_key_regに追加

        #print( format(reg , "080b"))
        return round_key, round_key_reg#段鍵，鍵スケジュール内部状態が格納された配列を返す

    
    def compute(self,p,round_key,ROUND):
        #クラス内で使うおおもとの暗号化関数
        #【引数】平文，段鍵が格納されたリスト，段数
        #【戻り値】暗号文（最終段の出力データ）
        
        x=p#内部状態をxとし，それに平文pを代入する

        #暗号化処理開始
        x^=round_key[0]#最初に段鍵をXOR
        for r in range(ROUND):
            x=self.s_layer(x,self.sbox,self.block_len)#S-Box層
            x=self.p_layer(x,self.perm)#転置層
            x^=round_key[r+1]#段鍵XOR
            
        y=x#変数ｙに最終的な内部状態xを代入
        return y#yを返す


    def encrypt(self,p):
        #クラス外で使う暗号化関数
        #【引数】平文 （秘密鍵はインスタンス生成時のものを使う）
        #【戻り値】暗号文         
        y=self.compute(p,self.round_key,self.ROUND)
        return y


    def test(self):
        #テストベクトルと一致するか確認してこのファイルにバグがないかをチェック
        #暗号化関数にcomputeを使うのは，テストベクトルの秘密鍵を使うためである
        
        check=0#チェック用の変数 0 ならテストに合格 1なら不合格
        for i in range( len(self.test_vector) ):#テストベクトルの本数だけ繰り返す
            #print("plain="+format(key[i] , "016x")+", key="+format(key[i] , "020x"))
            test_round_key, test_round_key_reg = self.key_sch( self.test_mas_key[i], self.full_round)#testメソッドでのみ使用する段鍵
            ciph=self.compute( self.test_plain[i], test_round_key, self.full_round)#テストベクトルの平文を暗号化する
            #print("ciph="+format(ciph , "016x")+", true cipher="+format(test_vector[i] , "016x"))
            if(ciph!=self.test_vector[i]):#テストベクトルと得られた暗号文ciphが不一致だったら
                check=1
        if(check==0):
            print("暗号器プログラムのテストに通りました！")#match with the test vecter
        else:
            print("暗号器プログラムのテストに通りません。ファイルのどこかにバグがあると考えられます。")#don't match with the test vecter
            input("処理を停止しました。続行する場合はEnterキーを押してください。")
