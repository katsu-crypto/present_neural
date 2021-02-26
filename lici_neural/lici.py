from block_ciph import *
from Crypto.Random import get_random_bytes#ランダム変数

class CiphMachine(Block_ciph):
    #暗号器のクラスCiphMachine
    #ブロック暗号向けの演算をまとめたBlock_ciphクラスを継承
    #秘密鍵はインスタンス生成時にランダムに設定
    
    def __init__(self,ROUND):
        #変数の定義など
        
        #------------------------------変更する必要のある変数-----------------------------------
        self.full_round=31#段数フルラウンド
        self.block_len=64#ブロック長
        self.word_len=32#ワード長 Feistelなので設定した
        self.key_len=128#秘密鍵長 
        self.sbox=[0x3,0xF,0xE,0x1,0x0,0xA,0x5,0x8,0xC,0x4,0xB,0x2,0x9,0x7,0x6,0xD]#S-Box
        #self.perm= 今回は必要ない
       
        #テストベクトルのデータ,秘密鍵，平文，暗号文の順番はそろえること
        self.test_mas_key=[0x00000000000000000000,0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF]#テストベクトルの秘密鍵
        self.test_plain=[0x0000000000000000,0x0000000000000000]#テストベクトルの平文
        self.test_vector=[0x7e7cea1868997560,0x198fa9d74394a18f]#テストベクトルの暗号文
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
        #Liciの段鍵は2つだが，ここでは2つ纏めて抽出し，暗号化関数の中で分割するとする．
        round_key_reg=[]#各段の鍵スケジュール内部状態を格納する配列
        #print(len(sbox))
        reg=key
        for r in range(ROUND):
            #print( format(reg , "080b"))
            round_key.append( self.extract(reg,0,63) )#段鍵の抽出
            reg=self.rotate_left_shift(reg,13,self.key_len)#13bit left rotate
            reg=self.s_apply(reg,self.sbox,0,self.key_len)#S-Box 0-3th bit
            reg=self.s_apply(reg,self.sbox,4,self.key_len)#S-Box 4-7th bit
            reg=self.round_count(reg,r,59,self.key_len)#段定数のXOR 59-63th bit
            round_key_reg.append( reg )#鍵スケジュール内部状態の抽出

        #print( format(reg , "080b"))
        return round_key, round_key_reg

    
    def compute(self,p,round_key,ROUND):
        #クラス内で使うおおもとの暗号化関数
        #【引数】平文，段鍵が格納されたリスト，段数
        #【戻り値】暗号文（最終段の出力データ）
        x_lsb=self.extract(p,0,31)#右側の内部状態に平文pの右半分を代入
        x_msb=self.extract(p,32,63)#左側の内部状態に平文pの左半分を代入
        #暗号化処理開始
        for r in range(ROUND):
            rk1=self.extract(round_key[r],0,31)#段鍵を分割
            rk2=self.extract(round_key[r],63,32)#段鍵を分割

            a=self.s_layer(x_msb,self.sbox,self.word_len)#S-Box層
            b=x_lsb^a^rk1#段鍵XOR
            c=self.rotate_left_shift(b,3,self.word_len)#3ビット左シフト
            d=a^rk2^c#段鍵XOR
            e=self.rotate_right_shift(d,7,self.word_len)#7ビット右シフト
            x_lsb=e
            x_msb=c
        y=x_msb<<32 ^ x_lsb#2つの内部状態の結合して変数ｙに代入
        return y#ｙを返す


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
