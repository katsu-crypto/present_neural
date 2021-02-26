class Block_ciph():
    #ブロック暗号に必要な演算処理をまとめたクラス
    #このクラスを継承させて暗号器プログラムを作る
    
    def print_bin(self,x,data_len):
        #データxを2進数出力
        #【引数】x データ ，data_len データ長
        for i in range(data_len):
            a=( x>>((data_len-i)-1) )&1
            print(a,end="")
        print("")
    
    def print_hex(self,x,data_len):
        #データxを16進数出力
        #【引数】x データ ，data_len データ長
        nibb_len=int(data_len/4)
        #print(nibb_len)
        for nibb in range(nibb_len):
            a=( x>>(( nibb_len-nibb-1 )*4) )&0xf
            #print( format(a,"x") ,end="")
            print( format(a,"x") ,end="")
        print("")

    def rotate_left_shift(self,x,num,data_len):
        # 左 に num ビット巡回シフト
        #【引数】x 入力データ，num シフトするビット数，data_len データ長
        #【戻り値】入力データを左にnumビットシフトさせた値
        
        if(num>=data_len):
            num=num%data_len
        y=x
        #if(num==0):
        #    return y
        mask_left =(2**num)-1
        mask_right=(2**(data_len-num)-1)
        right=x&mask_right
        left =(x>>(data_len-num))&mask_left
        y=right<<num ^ left
        return y

    def rotate_right_shift(self,x,num,data_len):
        # 右 に num ビット巡回シフト
        #【引数】x データ，num シフトするビット数，data_len データ長
        #【戻り値】入力データを右にnumビットシフトさせた値
        
        if(num>=data_len):
            num=num%data_len
        y=x
        #if(num==0):
        #    return y
        mask_right=(2**num)-1
        mask_left =(2**(data_len-num)-1)
        right=x&mask_right
        left =(x>>num)&mask_left
        y=right<<(data_len-num) ^ left
        return y

    def p_layer(self,x,perm):
        #転置層
        #【引数】x データ，転置の入出力関係のリスト
        #【戻り値】入力データを1ビット単位で転置させた値
        
        y=0
        for i in range(len(perm)):
            a=(x>>i)&1
            y^=a<<perm[i]
        return y

    def s_apply(self,x,sbox,num,data_len):
        #ある1箇所にだけS-Boxを適用するメソッド
        #【引数】x データ，s-boxのリスト(配列)，適用するビット位置(LSB)，データ長
        #【戻り値】入力データのnumビット目からnum+3ビット目に4ビットS-Boxを適用した値
        
        if(num>=data_len):
            num=num%data_len

        y=x
        s_in=(y>>num)&0xf#Input to S-box
        s_out=sbox[s_in]<<num#Output from S-Box
        mask_s=0xf<<num#s_boxを適用する箇所だけが１となっているマスク
        mask=(2**data_len)-1 - mask_s #s_boxを適用する箇所だけが０となっているマスク
        y=y&mask ^ s_out
        return y

    def s_layer(self,x,sbox,data_len):
        #S-Box層 データ全てに4ビット区切りでS-Boxを適用
        #【引数】入力データ，s_boxのリスト，データ長
        #【戻り値】入力データの全範囲に4ビットS-Boxを適用した値
        y=x
        for nibb in range( int(data_len/4) ):
            num=nibb*4
            y=self.s_apply(y,sbox,num,data_len)
        return y
    
    def round_count(self,x,r,num,data_len):
        #定数のXOR
        #【引数】入力データ,XORされる定数，適用するビット位置(LSB)，データ長
        #【戻り値】入力データのnumビット目に定数rをXORした値
        if(num>=data_len):
            num=num%data_len        
        y=x
        y^=(r)<<num
        return y

    def extract(self,x,a,b):
        #データx の a~bビット目を抽出 a,bは順不同でオッケー
        #【引数】入力データ，範囲1，範囲２
        #【戻り値】入力データのa~bビット目を抽出した値
        if(a>b):
            a_max=a
            a_min=b
        elif(a==b):
            return (x>>a)&1
        else:
            a_max=b
            a_min=a
        y=x

        y=y>>a_min
        mask=2**(a_max-a_min+1)-1
        return y&mask