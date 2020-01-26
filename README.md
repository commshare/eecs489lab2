# p2p 
- [实验2](http://web.eecs.umich.edu/~sugih/courses/eecs489/lab2.html)
## 对等节点

## EECS 489实验2：对等节点
> 该作业的截止日期为2016年1月22日（星期五）下午6点。
> 介绍
大多数套接字程序（包括Lab1的netimg）都遵循客户端-服务器范例，在该范例中，服务器在众所周知的端口上等待客户端的连接。在本实验中，我们将探索对等编程。对等点基本上既是服务器又是客户端。它接受来自其他对等方的连接，并且还连接到一个或多个对等方。
> 你提供了一个框架代码：源文件peer.cpp 和与之配套的头文件peer.h，作为本实验的一部分。您可以从“课程文件夹” 下载 支持代码。支持代码仅包含三个文件：Makefile，peer.h和 peer.cpp。提供的Makefile构建了一个名为peer的程序。它需要Lab 1中的netimg.h， socks.h和socks.cpp。您只需将Lab 2中的文件复制到Lab 1文件夹中即可。如果要保存Makefile请从实验1进行复制，然后再复制实验2的版本。该同行程序需要在命令行上两个可选参数：

> % peer [-p <hostname>:<port> -n <maxpeers> -v <version>]
该-p选项告诉同行，对等连接到最初计划。如果未提供此选项，则 对等方将作为服务器在随机的临时端口上侦听。在-n选项允许用户设置一个同行的最大的对等关系（仅在使用PA1）。该-v选项可为同一个选项同样netimg。

> 要引导对等（p2p）网络，我们首先自己启动一个对等网络。每次对等方运行时，它都会在屏幕/控制台上打印其完全限定的域名（FQDN）和正在侦听的端口号。当一个对等体以另一个对等体的hostname：port作为其命令行参数运行时，新对等体会尝试通过创建套接字并连接到对等体来加入p2p网络中的对等体。
当且仅当其对等表未满时，接收到加入请求的对等方才接受该对等体。无论是否接受加入请求，对等体都会 在其对等表中将对等主机的hostname：port发送回发出请求的对等体（如果该表不为空），以帮助新加入的对等体找到更多要加入的对等体。

- 我们将重用您为实验1编写的socks.cpp中的大多数功能。如果您没有设法使这些功能在实验1中工作，则可以获得20个PA1点的解决方案。

- 退后一步，放眼大局，看看在Lab 1的两个不同流程中实现的代码现在如何驻留在同一流程中，以及该流程如何充当客户端和服务器的角色。要特别注意如何使用由单个线程监视的多个套接字来完成此操作。本实验的另一个目标是使您早日了解协议设计。在这种情况下，我们正在设计带有重定向的简单对等连接协议。

### 任务1：服务器端
- 您的第一个任务是实现对等方的服务器端。您可以在代码中搜索字符串“ Task 1”，以查找必须填写与“ Task 1”相关的代码的位置。您可以在代码中搜索字符串“ YOUR CODE HERE”，以查找代码必须存储的位置。
- 如果对等方在命令行中不带任何选项运行，则其默认构造函数调用socks_servinit（server，sname，复用），服务器-> sin_port = 0，复用设置为1。因为我们将为两个接口都使用相同的端口号监听和连接套接字，在调用bind（）之前修改 socks_servinit（）以设置地址重用套接字选项。要将相同的地址和端口号绑定到多个套接字，在MacOS X和Windows上，通常只需设置套接字选项SO_REUSEADDR即可。但是在Linux上，除了SO_REUSEADDR之外，您还需要设置套接字选项SO_REUSEPORT。此外， 在Winsocks上未实现SO_REUSEPORT。为了在所有三个平台上实现可移植性，您应该同时设置两个套接字选项，但是要用#ifndef _WIN32保护 SO_REUSEPORT（后面紧跟#endif）。操作系统将为套接字分配一个随机的临时端口。最后，将套接字描述符返回给调用方。在socks_servinit（）中搜索“实验室2任务1”，以 查找代码应到达的位置。这应该不超过4至6行代码。回想一下实验1，从socks_servinit（）返回时，提供的self 参数包含当前主机的IPv4地址和绑定到返回的套接字的端口号。主机名进一步存储在提供的sname参数中。

设置对等对象后，在main（）中调用 select（）以等待侦听套接字上的连接（1至2行代码）。当select（）返回时，我们首先调用 peer：handlejoin（）来检查是否有新的对等方试图加入p2p网络。如果新对等方尝试连接到该对等方，并且该对等方的对等表未满，则handlejoin（）调用 socks_accept（）接受连接，然后调用 peer :: ack（）发送回带有pm_type字段设置的pmsg_t消息 到PM_WLCM。然后，新对等方存储在对等表中。另一方面，如果对等表已满，handlejoin（）像以前一样调用socks_accept（）和 peer :: ack（），但是在对peer :: ack（）的调用中 ，它发送回重定向（pm_type = PM_RDRT）消息。该功能对等:: ACK（TD，类型）执法官一起类型的消息pmsg_t中定义peer.h。它填补了该消息的字段：pm_vers必须设置为 PM_VERS，pm_type集到类型参数传递到对等体:: ACK（） 。所述pm_param字段保存对应于不同的参数值pm_type字段。对于 pm_type PR_WLCM和PR_RDRT，pm_param 字段保存连接到pmsg_t数据包的对等体的数量。如果对等表为空，则pm_param字段将设置为0。如果对等表不为空，则pm_param字段将设置为1（因为在本实验中，每个对等体最多允许2个伙伴）和对等体的结构sockaddr_in通过提供的套接字td发送到加入对等方。下图显示了发送的pmsg_t。


- 如果发送时发生任何错误，例如，如果连接的另一端已被对等方关闭，则关闭连接。这部分代码少于8行。

- 任务1就是全部。总共大约需要15行代码。完成任务1后，您应该先测试代码，然后再继续执行任务2。有关使用peer的参考实现测试代码的一些准则，请参见下面的“测试”部分 。

## 任务2：客户端
- 您可以在代码中搜索字符串“ Task 2”，以查找必须填写与“ Task 2”相关的代码的位置。
- 如果使用-p选项运行对等项，则用户必须提供一个已知的对等主机名和要连接的端口号，并且端口号与对等主机名之间用冒号分隔。提供的函数peer_args（）处理命令行解析。从调用返回到peer_args（）时，对等方的主机名将存储在提供的* pname中，而端口号将以网络字节顺序存储在 * port中。的对等物随后与已知的对等体的主机名和端口号构成。对等体默认构造函数通过调用socks_clninit（）连接到已知对等体。由于我们将重用相同的端口号以连接到其他对等方并侦听来自其他对等方的连接，因此您需要从实验1 扩展socks_clntinit（）来设置地址重用套接字选项。在socks_clntinit（）中搜索“实验室2任务2”，以 查找代码应到达的位置。您基本上可以为上面的“实验2任务1”剪切并粘贴相同的5行代码。从socks_clntinit（）返回后，已知对等方的地址和端口号存储在peer :: ptable的第一个元素中 。另外，操作系统会为连接的插座分配一个随机的临时源端口。找出分配的临时源端口号并将其存储在 自身中变量，以及当前主机的IPv4地址，就像您在实验1的socks_servinit（）中所做的一样。这也应该是两行代码。此时，在默认构造函数中，我们将在上面的任务1中调用socks_servinit（）函数。但是，与其使用self.sin_port = 0 调用该函数，不如通过与已知对等方连接时由OS分配的随机临时端口号进行调用。回到main（）中，select（）将等待连接到已知对等端的套接字以及您正在侦听其他对等端的套接字上的活动。

函数peer :: handlemsg（td，msg）检查每个连接的对等套接字上的活动。如果有传入数据包，它将调用 peer :: recvmsg（td，msg，peer），后者从提供的套接字td接收 pmsg_t消息。您需要首先检查收到的数据包的版本号。如果它的 pm_vers不是PM_VERS，那么我们真的不知道套接字的接收队列中有什么。在这种情况下，我们需要通过调用socks_clear（）清除队列中当前所有位的队列 （请参见下文）。假设版本号签出，如果pm_param数据包的字段不为0，因为在本实验中，我们假设最多将返回一个对等方，因此我们只是将对等方的peer_t接收到提供的 对等方参数中。如果接收数据包时出错，该函数将关闭套接字td并返回由套接字接收API返回的错误代码。否则，它将返回接收到的字节总数。您将编写 peer :: recvmsg（）函数-大约30行代码。

当套接字的接收队列中出现未知数据时，我们真的不知道它包含什么或如何处理它，因此，我们最好的办法就是简单地清除所有数据的接收队列并等待新数据到达。如果套接字是阻塞套接字，我们首先将其设置为非阻塞套接字，然后继续接收并“丢弃”当前驻留在接收队列中的所有数据，直到非阻塞接收告诉我们队列中没有更多数据为止。如果套接字是阻塞套接字，则需要将其恢复到阻塞状态。您将实现清除socks.cpp：socks_clear（）中的接收队列的过程。功能。所用代码不应超过7到10行。请注意，加入p2p网络的对等方只是连接到另一个对等方，而没有发送任何消息，因此，在-v命令行选项中使用不同的版本号 不会影响加入过程。

返回peer :: handlemsg（），在本实验中，带有错误版本号的消息只会导致打印出错误消息（我们将在PA1中的p2p搜索中更好地使用此功能）。如果版本号签出，则接收到携带另一个对等方的数据包会导致打印出第三对等方的地址和端口号。如果接收到的包的类型为PM_RDRT， handlemsg（）会通知用户该连接已被拒绝（重定向）并退出该过程。然后，用户可以 通过再次运行同级程序来手动尝试连接到重定向数据包中返回的第三个同级。

- 
这-就是任务2的全部内容。任务2的总行数应少于50行代码。两个任务的总行数应少于70行。

你没有需要处理同行离开P2P网络：曾经是同行的出发，不要求其合作伙伴对清理其对表，并准备接受另一同行。您可以假设仅当整个p2p网络都被拆除时，对等方才被拆除。这是必需的，但是，当对等的叶子，它的合作伙伴不会崩溃。

## 测试您的代码
我们将使用CAEN为该课程设置的相同四台主机。再次，不要使用CAEN的登录服务器（login.engin.umich.edu），它将把您重定向到caen-vnc *主机之一，因为这些主机不允许连接到它们的随机端口。您还可以在单​​个主机上运行多个对等端，并在它们之间形成p2p连接。当多个同龄人在同一主机上运行，你可以使用本地主机在命令行到位同级的主机名的同行。
除了骨骼代码和Makefile文件，我们还提供了可执行的二进制同行，叫 refpeer，上CAEN eecs489主机运行。可在/afs/umich.edu/class/eecs489/w16/lab2/上 获得。像在实验1中一样，这是Red Hat 7可执行文件，不可以下载也不可以在Mac OS X，Ubuntu或Windows计算机上运行。请记住，只能通过UMVPN，MWireless或从CAEN Lab桌面连接到CAEN eecs489主机。完成任务1后，应立即测试代码。使用refpeer连接到 对等端。同样，完成任务2后，将您的对等连接 到refpeer。要查看代码的预期行为，请运行多个refpeer并使它们彼此连接。

这是一个示例测试场景，假设您已经构建了程序对等并且该实验室位于该工作目录/文件夹中。在本地主机上创建四个窗口。

在第一个窗口上，将ssh切换到eecs489p1.engin.umich.edu，切换到该实验室的工作目录，运行 不带任何命令行参数的peer：
p1% ./peer

它应该打印到屏幕上（具有不同的端口号，此处以粗体显示）：

This peer address is caen-eecs489p1.engin.umich.edu:43945

。在四个eecs489主机上，而不是从笔记本电脑或CAEN Lab台式机​​上，可以将四个主机中的每一个称为p1至p4。
在第二个窗口上，将ssh切换到eecs489p2.engin.umich.edu，切换到该实验室的工作目录， 使用以下命令行参数运行peer（将端口号替换为上面第一项中打印的端口号）：
p2% ./peer -p p1:43945

它应该打印到屏幕上（具有不同的端口号）：

Connected to peer p1:43945
This peer address is eecs489p2.engin.umich.edu:56535
Received ack from p1:43945

同时，在第一个窗口上，您应该看到以下附加行打印到屏幕上：

Connected from peer p2:56535

在第三个窗口上，将ssh切换到eecs489p3.engin.umich.edu，切换到该实验的工作目录， 使用以下命令行参数运行peer（用上面第一项中的端口号替换端口号）：
p3% ./peer -p p1:43945

它应该打印到屏幕上（具有不同的端口号）：

Connected to peer p1:43945
This peer address is eecs489p3.engin.umich.edu:48141
Received ack from p1:43945
  which is peered with: p2:56535

同时，在第一个窗口上，您应该看到以下附加行打印到屏幕上：

Connected from peer p3:48141

在第四个窗口上，将ssh切换到eecs489p4.engin.umich.edu，切换到该实验室的工作目录， 并使用以下命令行参数运行peer（用上面第一项中的端口号替换端口号）：
p4% ./peer -p p1:43945

它应该打印到屏幕上（具有不同的端口号）：

Connected to peer p1:43945
This peer address is eecs489p4.engin.umich.edu:40231
Received ack from p1:43945
  which is peered with: p2:56535
Join redirected, try to connect to the peer above.
同时，在第一个窗口上，您应该看到以下附加行打印到屏幕上：

Peer table full: p4:40231 redirected

停留在第四个窗口上，使用以下命令行参数再次运行peer（用上面第四项中的端口号替换端口号）：
p4% ./peer -p p2:56535

它应该打印到屏幕上（具有不同的端口号）：

Connected to peer p2:56535
This peer address is eecs489p4.engin.umich.edu:50095
Received ack from p2:56535
  which is peered with: p1:43945

同时，在第二个窗口的eecs489p2上，应该在屏幕上看到以下附加行：

Connected from peer p4:50095

这样就结束了我们的示例测试场景，您可以退出所有四个同行。
上面是一个非常简单的测试用例，用于检查您的同级之间是否正在通信。您应该使用自己的其他测试案例进一步测试p2p网络。回想一下，如果对方退出，则不需要对方接受另一个对方。

## 投稿须知
与实验1一样，在本课程中，将公开可用的代码合并到您的解决方案中也被认为是作弊行为。与另一种算法一样，放弃一种算法的实现也被认为是作弊行为。如果无法实现所需的算法，则在上交作业时必须通知教学人员。
千万不要使用尚未在提供使用的任何库或编译器选项生成文件。这样做可能会使您的代码不可移植，并且如果我们无法编译您的代码，您将受到重罚。在CAEN eecs489主机上测试您的编译！您提交的内容必须编译和运行，而不 使用所提供的CAEN eecs489主机错误的Makefile， 未修改。

您的“ Lab2文件 ”包括peer.cpp和 socks.cpp文件，以及经过修改的peer.h（如果已修改）。

要上交Lab2，请将Lab2文件的压缩或压缩的tarball上传到CTools投递箱。保留自己的备份副本！您上传的文件上的时间戳就是您的提交时间。如果超过了截止日期，则您的提交将被视为延迟。只要您遵守截止日期，就可以进行多次“提交”，而没有后期政策的影响。我们强烈建议您使用私有的 第三方存储库，例如github或M + Box或Dropbox来保留提交的备份副本。本地时间戳很容易更改，不能用来确定文件的最后修改时间（-10点）。注意仅使用允许私有存储的第三方存储库访问。将您的代码放置在可公开访问的第三方存储库中是违反荣誉代码的行为。

仅上交已修改的文件。请勿上交我们提供的尚未修改的支持代码（-4分）。 请勿随您的作业（-4点）一起上交任何二进制文件（对象，可执行文件，dll，库或图像文件）。您的代码必须不需要Makefile中列出的外部库或头文件（-10点）。

不要删除所有printf（）或 cout和cerr，以及为调试目的添加的其他任何日志记录语句。您应该使用调试器进行调试，而不是使用printf（）进行调试。如果我们无法理解您的代码输出，您将得到零分。