# 从RFC6234中理解SHA2-256算法


### 一、前置知识点
SHA2-256算法是SHA第二代的算法，256指的是它的算法结果会产生256位数据，也就是32字节、64位长度的16进制字符。
### 二、算法流程
算法流程就不多做介绍，同其他哈希算法流程类似，都需要经历补位、填充长度以及分组，不同的是每轮循环所做的操作
#### 1 补位
基本一样，不做额外说明
#### 2 记录信息长度
同上
#### 3 初始化变量
依旧是从常量的初始化开始，根据结果256位来看，需要8个常量组成，常量的计算方式是取自自然数中前面8个素数(2,3,5,7,11,13,17,19)的平方根的小数部分的前32位，举例看
```
>>> 2**0.5-1
0.41421356237309515

0.41421356237309515=6*16^-1+a*16^-2+0&16^-3···
```
于是, 质数2的平方根的小数部分取前32位就对应0x6a09e667，据此类推，初始化常量的值就是
```c
m_state[0] = 0x6a09e667;
m_state[1] = 0xbb67ae85;
m_state[2] = 0x3c6ef372;
m_state[3] = 0xa54ff53a;
m_state[4] = 0x510e527f;
m_state[5] = 0x9b05688c;
m_state[6] = 0x1f83d9ab;
m_state[7] = 0x5be0cd19;
```
#### 4 处理分组数据
还是同样的套路，输入的数据被分成每512位一组，而512位的数据又被拆分成每32位一小组，一共是16个小组，SHA256的循环轮次和MD5是相同的，但是SHA256和SHA1一样，除了初始的16组是原始的以外，剩余的组都通过额外的公式来计算得来

根据文档
```
For t = 0 to 15
    Wt = M(i)t
For t = 16 to 63
    Wt = SSIG1(W(t-2)) + W(t-7) + SSIG0(w(t-15)) + W(t-16)
```
c++实现
```c
for (uint8_t i = 0, j = 0; i < 16; i++, j += 4) { // Split data in 32 bit blocks for the 16 first words
    m[i] = (m_data[j] << 24) | (m_data[j + 1] << 16) | (m_data[j + 2] << 8) | (m_data[j + 3]);
}

for (uint8_t k = 16 ; k < 64; k++) { // Remaining 48 blocks
    m[k] = SHA256::sig1(m[k - 2]) + m[k - 7] + SHA256::sig0(m[k - 15]) + m[k - 16];
}

uint32_t SHA256::sig0(uint32_t x) {
	return SHA256::rotr(x, 7) ^ SHA256::rotr(x, 18) ^ (x >> 3);
}

uint32_t SHA256::sig1(uint32_t x) {
	return SHA256::rotr(x, 17) ^ SHA256::rotr(x, 19) ^ (x >> 10);
}
```
针对64轮次每轮同样有常量，而SHA256的常量计算方式如下（取自自然数中前面64个素数的立方根的小数部分的前32位）
```c
unsigned int K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
    0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
    0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
    0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
    0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
    0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
    0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
    0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
    0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};
```
看下主处理流程
```
3. Perform the main hash computation:
    For t = 0 to 63
        T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt
        T2 = BSIG0(a) + MAJ(a,b,c)
        h = g
        g = f
        f = e
        e = d + T1
        d = c
        c = b
        b = a
        a = T1 + T2
```
出现T1、T2两个中间变量，涉及到了4个函数
```
CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)

MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)

BSIG0(x) = ROTR^2(x) XOR ROTR^13(x) XOR ROTR^22(x)

BSIG1(x) = ROTR^6(x) XOR ROTR^11(x) XOR ROTR^25(x)
```
c++来实现
```c
maj   = SHA256::majority(state[0], state[1], state[2]);
xorA  = SHA256::rotr(state[0], 2) ^ SHA256::rotr(state[0], 13) ^ SHA256::rotr(state[0], 22);

ch = choose(state[4], state[5], state[6]);

xorE  = SHA256::rotr(state[4], 6) ^ SHA256::rotr(state[4], 11) ^ SHA256::rotr(state[4], 25);

sum  = m[i] + K[i] + state[7] + ch + xorE;
newA = xorA + maj + sum;
newE = state[3] + sum;

state[7] = state[6];
state[6] = state[5];
state[5] = state[4];
state[4] = newE;
state[3] = state[2];
state[2] = state[1];
state[1] = state[0];
state[0] = newA;
```
最终只需要将得到的8个变量重新赋值再作为初始变量传递给下一分组计算即可
#### 5 输出结果
在经过分组计算后能够得到A、B、C、D、E、F、G、H，从低位字节A开始，高位字节E结束

### 总结
在了解了MD5、SHA1算法之后再来看SHA2-256算法的话，很明显能发现SHA2-256结合了前两个算法，包括MD5的每轮次的不同常量以及SHA1的数据分组方式以及每轮次计算方式，并且来降低了计算的轮次，引入更多的空间来替换计算时间效率的提升
