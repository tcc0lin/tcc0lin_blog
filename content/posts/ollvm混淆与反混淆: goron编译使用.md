---
title: "Ollvm混淆与反混淆: Goron编译使用"
date: 2024-03-29T23:21:45+08:00
draft: true
author: "tcc0lin"
tags: ["goron框架"]
categories: ["ollvm混淆与反混淆"]
---
很多App实现的定制ollvm框架中都有goron框架的影子，或多或少的借鉴了它的功能，包括
- 间接跳转,并加密跳转目标(-mllvm -irobf-indbr)
- 间接函数调用,并加密目标函数地址(-mllvm -irobf-icall)
- 间接全局变量引用,并加密变量地址(-mllvm -irobf-indgv)
- 字符串(c string)加密功能(-mllvm -irobf-cse)
- 过程相关控制流平坦混淆(-mllvm -irobf-cff)

想要了解怎么针对这些混淆功能完成去混淆，势必要先对其混淆过程有所了解，那么第一步就是对goron框架的编译使用

### 一、环境配置
- 环境：MacBook Pro 16G
- cmake：cmake version 3.26.3
- Android Studio NDK：21.1.6352462
### 二、编译过程
#### 2.1 工程选定
```shell
git clone https://github.com/amimo/goron.git
cd goron
git checkout llvm-9.0.0
```
#### 2.2 编译
```shell
mkdir build && cd build
```
建好产出目录
```
cmake -DCMAKE_BUILD_TYPE=Release -DLLVM_ENABLE_ASSERTIONS=ON -DLLVM_ENABLE_PROJECTS=clang -G "Unix Makefiles" -DCMAKE_INSTALL_PREFIX=/Path/You/Install/Dir/llvm-project-install ../llvm
make -j12 install
```
LLVM_ENABLE_PROJECTS：参数只需开启clang编译器一个工程即可
CMAKE_INSTALL_PREFIX：（可选参数）设置编译后可执行文件、动态库、静态库、头文件等等统一的放置路径

编译完成之后就可以在bin目录下看到这些可执行文件了
```shell
FileCheck                       llvm-cat                        llvm-opt-fuzzer
arcmt-test                      llvm-cfi-verify                 llvm-opt-report
bugpoint                        llvm-config                     llvm-pdbutil
c-arcmt-test                    llvm-cov                        llvm-profdata
c-index-test                    llvm-cvtres                     llvm-ranlib
clang                           llvm-cxxdump                    llvm-rc
clang++                         llvm-cxxfilt                    llvm-readelf
clang-9                         llvm-cxxmap                     llvm-readobj
clang-check                     llvm-diff                       llvm-rtdyld
clang-cl                        llvm-dis                        llvm-size
```
### 三、集成到NDK
替换原有的NDK目录下的clang文件即可，首先在local.properties中配置好ndk.dir，接着替换clang、clang++文件即可
```shell
cp /Path/You/Install/Dir/llvm-project-install/bin/clang-9 /You/NDK/Path/Android/sdk/ndk/21.1.6352462/toolchains/llvm/prebuilt/darwin-x86_64/bin/clang
cp /Path/You/Install/Dir/llvm-project-install/bin/clang-9 /You/NDK/Path/Android/sdk/ndk/21.1.6352462/toolchains/llvm/prebuilt/darwin-x86_64/bin/clang++
```
配置完clang之后还需要在build.gradle中配置需要混淆组件，如下
```shell
defaultConfig {
    applicationId "com.example.myapplication"
    minSdk 24
    targetSdk 33
    versionCode 1
    versionName "1.0"

    testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"

    externalNativeBuild {
        cmake {
            cppFlags "-mllvm -irobf-cff"
        }
    }
}
```
配合so函数如下
```c++
#include <jni.h>
#include <string>

char text[256] = {0};
extern "C" JNIEXPORT jstring JNICALL
Java_com_example_myapplication_MainActivity_stringFromJNI(
        JNIEnv* env,
        jobject /* this */,
        jint val) {
    if (val == 0) {
        strcpy(text, "Hello from C++");
    }
    else if (val == 1) {
        strcpy(text, "value is 1");
    }
    else if (val == 2) {
        strcpy(text, "value is 2");
    }
    else if (val == 4) {
        strcpy(text, "value is 4");
    }
    else if (val == 8) {
        strcpy(text, "value is 8");
    }
    else if (val == 16) {
        strcpy(text, "value is 16");
    }
    else if (val == 32) {
        strcpy(text, "value is 32");
    }
    else if (val == 64) {
        strcpy(text, "value is 64");
    }
    else if (val == 3) {
        strcpy(text, "value is 3");
    }
    else if (val == 65535) {
        strcpy(text, "value is 65535");
    }
    else {
        strcpy(text, "value is default");
    }
    return env->NewStringUTF(text);
}
```
运行查看效果
### 四、混淆效果对比
- fla混淆后的效果
    ![](https://github.com/tcc0lin/self_pic/blob/main/fla.png?raw=true)
- cse混淆后的效果
    ![](https://github.com/tcc0lin/self_pic/blob/main/cse.png?raw=true)
    ![](https://github.com/tcc0lin/self_pic/blob/main/cse1.png?raw=true)
    每个字符都对应一个加密函数
- indgv混淆后的效果
    ![](https://github.com/tcc0lin/self_pic/blob/main/indgv.png?raw=true)
    字符串都通过全局变量来获取
- icall混淆后的效果
    ![](https://github.com/tcc0lin/self_pic/blob/main/icall.png?raw=true)
- indbr混淆后的效果
    ![](https://github.com/tcc0lin/self_pic/blob/main/indbr.png?raw=true)
    截断了函数流程