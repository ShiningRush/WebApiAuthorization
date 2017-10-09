# 获取全院RestApi授权Token封装库

该类封装了全院RestApi的授权Token获取流程，包括自动刷新Token。

该GitHub上的源码为 `Java `版本。

`c#` 版本请直接在Nuget中搜索 `Yiban.CoreService.Client` 或 在 Nuget 控制台下运行

    Install-Package Yiban.CoreService.Client

使用Demo 请参考 main.java 中的代码，另外该类开放了接口方便注入以及单元测试，有需要的可以使用。

调用步骤如下：

1，首先调用 `CredentialManager.Init` 方法设置好各项配置，如下所示：

    CredentialManager.Init(
				"your appId", // 你的appId
				"your secret", // 你的secret
				"192.168.27.32",  // 网关地址
				"53001", // 网关端口
				30); // 最小请求间隔时间，应该小于你程序调用网关接口的最小间隔时间

2,调用 `CredentialManager.getInstance().getAccessToken()` 获取Token

    CredentialManager.getInstance().getAccessToken()
    
