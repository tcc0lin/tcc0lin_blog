---
title: "基于Kernel Kprobe机制的改机架构实现"
date: 2024-03-27T18:51:18+08:00
draft: true
author: "tcc0lin"
tags:
    - 内核编译
    - 内核改机
categories:
    - 系统定制
---

### 一、背景
如上文[Linux Kprobe原理探究
](https://tcc0lin.github.io/linux-kprobe%E5%8E%9F%E7%90%86%E6%8E%A2%E7%A9%B6/)所提及的，Kprobe有多种玩法，在设备改机场景中可以通过对内核系统函数的篡改以完成改机的目的，本文就是基于Kernel Kprobe机制来搭建一套完整的改机架构

### 二、思路
从整体流程上看，Kprobe的实现是基于LKM的，那么编译方式、生效时机、更新方式都需要参考LKM的做法
![](https://github.com/tcc0lin/self_pic/blob/main/kprobe.png?raw=true)

### 三、具体执行
#### 3.1 LKM编译
#### 3.2 patch init.rc
#### 3.3 insmod ko