### 1 Spring Security应用详解

#### 1.1 工作原理

##### 1.1.1 结构总览

Spring Security所解决的问题就是**安全访问控制**，而安全访问控制功能其实就是对所有进入系统的请求进行拦截， 校验每个请求是否能够访问它所期望的资源。根据前边知识的学习，可以通过Filter或AOP等技术来实现，Spring Security对Web资源的保护是靠Filter实现的，所以从这个Filter来入手，逐步深入Spring Security原理。 当初始化Spring Security时，会创建一个名为 `springSecurityFilterChain` 的Servlet过滤器，类型为 org.springframework.security.web.FilterChainProxy，它实现了javax.servlet.Filter，因此外部的请求会经过此 类，下图是Spring Security过滤器链结构图：

FilterChainProxy是一个代理，真正起作用的是FilterChainProxy中SecurityFilterChain所包含的各个Filter，同时 这些Filter作为Bean被Spring管理，它们是Spring Security核心，各有各的职责，但他们并不直接处理用户的认 证，也不直接处理用户的授权，而是把它们交给了认证管理器（AuthenticationManager）和决策管理器 （AccessDecisionManager）进行处理，下图是FilterChainProxy相关类的UML图示。

![](C:\Users\Aiden\Desktop\PlantUML\Spring Security\SpringSecurityFilterChain.png)







Spring Security功能的实现主要由一系列的过滤器链相互配合完成。

图

下面介绍过滤器链中主要的几个过滤器及作用：

`SecurityContextPersistenceFilter` 这个Filter是整个拦截过程的入口和出口（也就是第一个和最后一个拦截 器），会在请求开始时从配置好的 SecurityContextRepository 中获取 SecurityContext，然后把它设置给 SecurityContextHolder。在请求完成后将 SecurityContextHolder 持有的 SecurityContext 再保存到配置好 的 SecurityContextRepository，同时清除 securityContextHolder 所持有的 SecurityContext； `UsernamePasswordAuthenticationFilter` 用于处理来自表单提交的认证。该表单必须提供对应的用户名和密 码，其内部还有登录成功或失败后进行处理的 AuthenticationSuccessHandler 和 AuthenticationFailureHandler，这些都可以根据需求做相关改变；

 `FilterSecurityInterceptor` 是用于保护web资源的，使用AccessDecisionManager对当前用户进行授权访问，前面已经详细介绍过了；

 `ExceptionTranslationFilter` 能够捕获来自 FilterChain 所有的异常，并进行处理。但是它只会处理两类异常： AuthenticationException 和 AccessDeniedException，其它的异常它会继续抛出。

###### 1.1.1.1 认证流程

![SpringSecurityAuthenticationFlow](C:\Users\Aiden\Desktop\PlantUML\Spring Security\SpringSecurityAuthenticationFlow.png)

认证过程如下： 

1. 用户提交用户名、密码被SecurityFilterChain中的 `UsernamePasswordAuthenticationFilter` 过滤器获取到， 封装为请求Authentication，通常情况下是UsernamePasswordAuthenticationToken这个实现类。 

2. 然后过滤器将Authentication提交至认证管理器（AuthenticationManager）进行认证 

3. 认证成功后，`AuthenticationManager` 身份管理器返回一个被填充满了信息的（包括上面提到的权限信息， 身份信息，细节信息，但密码通常会被移除） Authentication 实例。 

4. `SecurityContextHolder` 安全上下文容器将第3步填充了信息的 Authentication ，通过 SecurityContextHolder.getContext().setAuthentication(…)方法，设置到其中。

   可以看出AuthenticationManager接口（认证管理器）是认证相关的核心接口，也是发起认证的出发点，它 的实现类为ProviderManager。而Spring Security支持多种认证方式，因此ProviderManager维护着一个 `List<AuthenticationProvider>` 列表，存放多种认证方式，最终实际的认证工作是由 AuthenticationProvider完成的。咱们知道web表单的对应的AuthenticationProvider实现类为 DaoAuthenticationProvider，它的内部又维护着一个UserDetailsService负责UserDetails的获取。最终 AuthenticationProvider将UserDetails填充至Authentication。 认证核心组件的大体关系如下：

   ![SpringSecurityAuthentication](C:\Users\Aiden\Desktop\PlantUML\Spring Security\SpringSecurityAuthentication.png)

###### 1.1.1.2 AuthenticationProvider 

通过前面的`Spring Security`认证流程我们得知，认证管理器（AuthenticationManager）委托 AuthenticationProvider完成认证工作。 

AuthenticationProvider是一个接口，定义如下：

``` Java
public interface AuthenticationProvider { 
    Authentication authenticate(Authentication authentication) throws AuthenticationException; 
    boolean supports(Class<?> var1); 
}
```

 `authenticate()`方法定义了`认证的实现过程`，它的参数是一个Authentication，里面包含了登录用户所提交的用 户、密码等。而返回值也是一个Authentication，这个Authentication则是在认证成功后，将用户的权限及其他信 息重新组装后生成。 

Spring Security中维护着一个 `List<AuthenticationProvider>` 列表，存放多种认证方式，不同的认证方式使用不 同的AuthenticationProvider。如使用用户名密码登录时，使用AuthenticationProvider1，短信登录时使用 AuthenticationProvider2等等这样的例子很多。 

每个AuthenticationProvider需要实现supports()方法来表明自己支持的认证方式，如我们使用表单方式认证， 在提交请求时Spring Security会生成UsernamePasswordAuthenticationToken，它是一个Authentication，里面 封装着用户提交的用户名、密码信息。而对应的，哪个AuthenticationProvider来处理它？

 我们在DaoAuthenticationProvider的基类AbstractUserDetailsAuthenticationProvider发现以下代码：

``` Java
public boolean supports(Class<?> authentication) { 
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication); 
}
```

 也就是说当web表单提交用户名密码时，Spring Security由DaoAuthenticationProvider处理。

最后，我们来看一下Authentication(认证信息)的结构，它是一个接口，UsernamePasswordAuthenticationToken就是它的实现之一：

```Java
public interface Authentication extends Principal, Serializable { 	(1)
	Collection<? extends GrantedAuthority> getAuthorities(); 		(2)
    Object getCredentials(); 										(3)
    Object getDetails(); 											(4)
    Object getPrincipal(); 											(5)
    boolean isAuthenticated(); 
    void setAuthenticated(boolean var1) throws IllegalArgumentException;
} 
```

（1）Authentication是spring security包中的接口，直接继承自Principal类，而Principal是位于 java.security 包中的。它是表示着一个抽象主体身份，任何主体都有一个名称，因此包含一个getName()方法。 

（2）getAuthorities()，权限信息列表，默认是GrantedAuthority接口的一些实现类，通常是代表权限信息的一系 列字符串。 

（3）getCredentials()，凭证信息，用户输入的密码字符串，在认证过后通常会被移除，用于保障安全。 

（4）getDetails()，细节信息，web应用中的实现接口通常为 WebAuthenticationDetails，它记录了访问者的ip地 址和sessionId的值。 

（5）`getPrincipal()`，身份信息，大部分情况下返回的是UserDetails接口的实现类，UserDetails代表用户的详细 信息，那从Authentication中取出来的UserDetails就是当前登录用户信息，它也是框架中的常用接口之一。

###### 1.1.1.3 UserDetailsService

1）认识UserDetailsService 

现在咱们现在知道DaoAuthenticationProvider处理了web表单的认证逻辑，认证成功后既得到一个 Authentication(UsernamePasswordAuthenticationToken实现)，里面包含了身份信息（Principal）。这个身份 信息就是一个 `Object` ，大多数情况下它可以被强转为UserDetails对象。 

DaoAuthenticationProvider中包含了一个UserDetailsService实例，它负责根据用户名提取用户信息 UserDetails(包含密码)，而后DaoAuthenticationProvider会去对比UserDetailsService提取的用户密码与用户提交 的密码是否匹配作为认证成功的关键依据，因此可以通过将自定义的 `UserDetailsService` 公开为spring bean来定 义自定义身份验证。

```Java
public interface UserDetailsService { 
    UserDetails loadUserByUsername(String username) throws UsernameNotFoundException; 
}
```

很多人把DaoAuthenticationProvider和UserDetailsService的职责搞混淆，其实UserDetailsService只负责从特定 的地方（通常是数据库）加载用户信息，仅此而已。而DaoAuthenticationProvider的职责更大，它完成完整的认 证流程，同时会把UserDetails填充至Authentication。

上面一直提到UserDetails是用户信息，咱们看一下它的真面目：

```Java
public interface UserDetails extends Serializable { 
    Collection<? extends GrantedAuthority> getAuthorities(); 
    String getPassword(); 
    String getUsername(); 
    boolean isAccountNonExpired(); 
    boolean isAccountNonLocked(); 
    boolean isCredentialsNonExpired(); 
    boolean isEnabled(); 
}
```

它和Authentication接口很类似，比如它们都拥有username，authorities。Authentication的getCredentials()与 UserDetails中的getPassword()需要被区分对待，前者是用户提交的密码凭证，后者是用户实际存储的密码，认证 其实就是对这两者的比对。Authentication中的getAuthorities()实际是由UserDetails的getAuthorities()传递而形 成的。还记得Authentication接口中的getDetails()方法吗？其中的UserDetails用户详细信息便是经过了 AuthenticationProvider认证之后被填充的。 

通过实现UserDetailsService和UserDetails，我们可以完成对用户信息获取方式以及用户信息字段的扩展。

Spring Security提供的InMemoryUserDetailsManager(内存认证)，JdbcUserDetailsManager(jdbc认证)就是 UserDetailsService的实现类，主要区别无非就是从内存还是从数据库加载用户。

###### 1.1.1.4 PasswordEncoder

1）认识PasswordEncoder 

DaoAuthenticationProvider认证处理器通过UserDetailsService获取到UserDetails后，它是如何与请求 Authentication中的密码做对比呢？

 在这里Spring Security为了适应多种多样的加密类型，又做了抽象，DaoAuthenticationProvider通过 PasswordEncoder接口的matches方法进行密码的对比，而具体的密码对比细节取决于实现：

```Java
public interface PasswordEncoder { 
    String encode(CharSequence var1); 
    matches(CharSequence var1, String var2); 
    default boolean upgradeEncoding(String encodedPassword) { 
        return false; 
    } 
}
```

而Spring Security提供很多内置的PasswordEncoder，能够开箱即用，使用某种PasswordEncoder只需要进行如 下声明即可，如下：

```Java
@Bean 
	public PasswordEncoder passwordEncoder() { 
        return NoOpPasswordEncoder.getInstance(); 
    }
}
```

NoOpPasswordEncoder采用字符串匹配方法，不对密码进行加密比较处理，密码比较流程如下： 

1、用户输入密码（明文 ）

2、DaoAuthenticationProvider获取UserDetails（其中存储了用户的正确密码） 

3、DaoAuthenticationProvider使用PasswordEncoder对输入的密码和正确的密码进行校验，密码一致则校验通 过，否则校验失败。

NoOpPasswordEncoder的校验规则拿 输入的密码和UserDetails中的正确密码进行字符串比较，字符串内容一致 则校验通过，否则 校验失败。

实际项目中推荐使用BCryptPasswordEncoder, Pbkdf2PasswordEncoder, SCryptPasswordEncoder等，感兴趣 的大家可以看看这些PasswordEncoder的具体实现。 

2）使用BCryptPasswordEncoder 

1、配置BCryptPasswordEncoder 在安全配置类中定义：

```Java
@Bean 
public PasswordEncoder passwordEncoder() { 
    return new BCryptPasswordEncoder(); 
}
```

##### 1.1.2 授权流程

###### 1.1.2.1 授权流程

Spring Security可以通过 http.authorizeRequests() 对web请求进行授权保护。Spring Security使用标准Filter建立了对web请求的拦截，最终实现对资源的授权访问。

Spring Security授权流程如下：

![](C:\Users\Aiden\Desktop\PlantUML\Spring Security\SpringSecurityAuthorizationFlow.png)

分析授权流程： 

1. 拦截请求，已认证用户访问受保护的web资源将被SecurityFilterChain中的 FilterSecurityInterceptor 的子 类拦截。

2. 获取资源访问策略，FilterSecurityInterceptor会从 `SecurityMetadataSource` 的子类 `DefaultFilterInvocationSecurityMetadataSource` 获取要访问当前资源所需要的权限 `Collection<ConfigAttribute>` 。

   SecurityMetadataSource其实就是读取访问策略的抽象，而读取的内容，其实就是我们配置的访问规则， 读 取访问策略如：

```Java
http
    .authorizeRequests() 
    .antMatchers("/r/r1").hasAuthority("p1") 
    .antMatchers("/r/r2").hasAuthority("p2")
	...
```

3. 最后，FilterSecurityInterceptor会调用 AccessDecisionManager 进行授权决策，若决策通过，则允许访问资 源，否则将禁止访问。

AccessDecisionManager（访问决策管理器）的核心接口如下:

```Java
public interface AccessDecisionManager { 
    /** * 通过传递的参数来决定用户是否有访问对应受保护资源的权限 */ 
    void decide(Authentication authentication , Object object, Collection<ConfigAttribute> configAttributes ) throws AccessDeniedException, InsufficientAuthenticationException; 
    //略.. 
}
```

这里着重说明一下decide的参数： 

authentication：要访问资源的访问者的身份 

object：要访问的受保护资源，web请求对应FilterInvocation 

configAttributes：是受保护资源的访问策略，通过SecurityMetadataSource获取。

**decide接口就是用来鉴定当前用户是否有访问对应受保护资源的权限。**

###### 1.1.2.2 授权决策

AccessDecisionManager采用**投票**的方式来确定是否能够访问受保护资源。

![](C:\Users\Aiden\Desktop\PlantUML\Spring Security\SpringSecurityAuthorization.png)

通过上图可以看出，AccessDecisionManager中包含的一系列AccessDecisionVoter将会被用来对Authentication 是否有权访问受保护对象进行投票，AccessDecisionManager根据投票结果，做出最终决策。

AccessDecisionVoter是一个接口，其中定义有三个方法，具体结构如下所示。

```Java
public interface AccessDecisionVoter<S> { 
    int ACCESS_GRANTED = 1; 
    int ACCESS_ABSTAIN = 0; 
    int ACCESS_DENIED = ‐1; 
    boolean supports(ConfigAttribute var1); 
    boolean supports(Class<?> var1); 
    int vote(Authentication var1, S var2, Collection<ConfigAttribute> var3); 
}
```

vote()方法的返回结果会是AccessDecisionVoter中定义的三个常量之一。ACCESS_GRANTED表示同意， ACCESS_DENIED表示拒绝，ACCESS_ABSTAIN表示弃权。如果一个AccessDecisionVoter不能判定当前 Authentication是否拥有访问对应受保护对象的权限，则其vote()方法的返回值应当为弃权ACCESS_ABSTAIN。 Spring Security内置了三个基于投票的AccessDecisionManager实现类如下，它们分别是 **AffirmativeBased**、**ConsensusBased**和**UnanimousBased**。

 **AffirmativeBased**的逻辑是： 

（1）只要有AccessDecisionVoter的投票为ACCESS_GRANTED则同意用户进行访问； 

（2）如果全部弃权也表示通过； 

（3）如果没有一个人投赞成票，但是有人投反对票，则将抛出AccessDeniedException。 Spring security默认使用的是AffirmativeBased。

 **ConsensusBased**的逻辑是： 

（1）如果赞成票多于反对票则表示通过。 

（2）反过来，如果反对票多于赞成票则将抛出AccessDeniedException。 

（3）如果赞成票与反对票相同且不等于0，并且属性allowIfEqualGrantedDeniedDecisions的值为true，则表 示通过，否则将抛出异常AccessDeniedException。参数allowIfEqualGrantedDeniedDecisions的值默认为true。

（4）如果所有的AccessDecisionVoter都弃权了，则将视参数allowIfAllAbstainDecisions的值而定，如果该值 为true则表示通过，否则将抛出异常AccessDeniedException。参数allowIfAllAbstainDecisions的值默认为false。 **UnanimousBased**的逻辑与另外两种实现有点不一样，另外两种会一次性把受保护对象的配置属性全部传递 给AccessDecisionVoter进行投票，而UnanimousBased会一次只传递一个ConfigAttribute给 AccessDecisionVoter进行投票。这也就意味着如果我们的AccessDecisionVoter的逻辑是只要传递进来的 ConfigAttribute中有一个能够匹配则投赞成票，但是放到UnanimousBased中其投票结果就不一定是赞成了。 UnanimousBased的逻辑具体来说是这样的： 

（1）如果受保护对象配置的某一个ConfigAttribute被任意的AccessDecisionVoter反对了，则将抛出 AccessDeniedException。 

（2）如果没有反对票，但是有赞成票，则表示通过。 

（3）如果全部弃权了，则将视参数allowIfAllAbstainDecisions的值而定，true则通过，false则抛出 AccessDeniedException。 Spring Security也内置一些投票者实现类如RoleVoter、AuthenticatedVoter和WebExpressionVoter等，可以 自行查阅资料进行学习。

#### 1.2 会话

用户认证通过后，为了避免用户的每次操作都进行认证可将用户的信息保存在会话中。spring security提供会话管 理，认证通过后将身份信息放入SecurityContextHolder上下文，SecurityContext与当前线程进行绑定，方便获取 用户身份。

##### 1.2.1 获取用户身份

Spring Security获取当前登录用户信息的方法为SecurityContextHolder.getContext().getAuthentication()

##### 1.2.2 会话控制

我们可以通过以下选项准确控制会话何时创建以及Spring Security如何与之交互：

|    机制    | 描述                                                         |
| :--------: | ------------------------------------------------------------ |
|   always   | 如果没有session就创建一个                                    |
| ifRequired | 如果需要就创建一个session（默认）登录时                      |
|   never    | SpringSecurity 将不会创建Session，但是如果应用中其他地方创建了Session，那么Spring Security将会使用它。 |
| stateless  | SpringSecurity将绝对不会创建Session，也不使用Session         |

通过以下配置方式对该选项进行配置：

```Java
@Override 
protected void configure(HttpSecurity http) throws Exception { 
    http.sessionManagement()
        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) 
}
```

默认情况下，Spring Security会为每个登录成功的用户会新建一个Session，就是**ifRequired** 。 

若选用never，则指示Spring Security对登录成功的用户不创建Session了，但若你的应用程序在某地方新建了 session，那么Spring Security会用它的。 

若使用stateless，则说明Spring Security对登录成功的用户不会创建Session了，你的应用程序也不会允许新建 session。并且它会暗示不使用cookie，所以每个请求都需要重新进行身份验证。这种无状态架构适用于REST API 及其无状态认证机制。

**会话超时**

可以在sevlet容器中设置Session的超时时间，如下设置Session有效期为3600s；

 spring boot 配置文件： 

```properties
server.servlet.session.timeout=3600s
```

session超时之后，可以通过Spring Security 设置跳转的路径。

```Java
http.sessionManagement() 
    .expiredUrl("/login‐view?error=EXPIRED_SESSION") 
    .invalidSessionUrl("/login‐view?error=INVALID_SESSION");
```

expired指session过期，invalidSession指传入的sessionid无效。

**安全会话cookie**

我们可以使用httpOnly和secure标签来保护我们的会话cookie：

	*  **httpOnly**：如果为true，那么浏览器脚本将无法访问cookie 
	*  **secure**：如果为true，则cookie将仅通过HTTPS连接发送

spring boot 配置文件：

```Java
server.servlet.session.cookie.http‐only=true 
server.servlet.session.cookie.secure=true
```

#### 1.3 授权

##### 1.3.1 概述

授权的方式包括 web授权和方法授权，web授权是通过 url拦截进行授权，方法授权是通过 方法拦截进行授权。他 们都会调用accessDecisionManager进行授权决策，若为web授权则拦截器为FilterSecurityInterceptor；若为方 法授权则拦截器为MethodSecurityInterceptor。如果同时通过web授权和方法授权则先执行web授权，再执行方 法授权，最后决策通过，则允许访问资源，否则将禁止访问。

类图如下所示：



##### 1.3.2 web授权

保护URL常用的方法有： 

**authenticated()** 保护URL，需要用户登录 

**permitAll()** 指定URL无需保护，一般应用与静态资源文件 

**hasRole(String role)** 限制单个角色访问，角色将被增加 “ROLE_” .所以”ADMIN” 将和 “ROLE_ADMIN”进行比较

**hasAuthority(String authority)** 限制单个权限访问 

**hasAnyRole(String… roles)**允许多个角色访问

**hasAnyAuthority(String… authorities)** 允许多个权限访问

**access(String attribute)** 该方法使用 SpEL表达式, 所以可以创建复杂的限制

**hasIpAddress(String ipaddressExpression)** 限制IP地址或子网

##### 1.3.3 方法授权

从Spring Security2.0版 本开始，它支持服务层方法的安全性的支持。本节学习@PreAuthorize,@PostAuthorize, @Secured三类注解。 

我们可以在任何 `@Configuration` 实例上使用 `@EnableGlobalMethodSecurity` 注释来启用基于注解的安全性。

以下内容将启用Spring Security的 `@Secured` 注释。

```Java
@EnableGlobalMethodSecurity(securedEnabled = true) public class MethodSecurityConfig {// ...}
```

然后向方法（在类或接口上）添加注解就会限制对该方法的访问。 Spring Security的原生注释支持为该方法定义了 一组属性。 这些将被传递给AccessDecisionManager以供它作出实际的决定：

```Java
public interface BankService
	@Secured("IS_AUTHENTICATED_ANONYMOUSLY") 
	public Account readAccount(Long id); 
	
	@Secured("IS_AUTHENTICATED_ANONYMOUSLY") 
	public Account[] findAccounts(); 
	
	@Secured("ROLE_TELLER") 
	public Account post(Account account, double amount); 
} 
```

以上配置标明readAccount、findAccounts方法可匿名访问，底层使用WebExpressionVoter投票器，可从 AffirmativeBased第23行代码跟踪。。

post方法需要有TELLER角色才能访问，底层使用RoleVoter投票器。

使用如下代码可启用prePost注解的支持

```Java
@EnableGlobalMethodSecurity(prePostEnabled = true) 
public class MethodSecurityConfig { 
// ... 
} 
```

相应Java代码如下：

```Java
public interface BankService { 
    @PreAuthorize("isAnonymous()") 
    public Account readAccount(Long id); 
    
    @PreAuthorize("isAnonymous()") 
    public Account[] findAccounts(); 
    
    @PreAuthorize("hasAuthority('p_transfer') and hasAuthority('p_read_account')") 
    public Account post(Account account, double amount); 
}
```

以上配置标明readAccount、findAccounts方法可匿名访问，post方法需要同时拥有p_transfer和p_read_account 权限才能访问，底层使用WebExpressionVoter投票器，可从AffirmativeBased第23行代码跟踪。

### 2 分布式系统认证方案

#### 2.1 什么是分布式系统

随着软件环境和需求的变化 ，软件的架构由单体结构演变为分布式架构，具有分布式架构的系统叫分布式系统，分 布式系统的运行通常依赖网络，它将单体结构的系统分为若干服务，服务之间通过网络交互来完成用户的业务处 理，当前流行的微服务架构就是分布式系统架构，如下图：



分布式系统具体如下基本特点： 

1、分布性：每个部分都可以独立部署，服务之间交互通过网络进行通信，比如：订单服务、商品服务。

2、伸缩性：每个部分都可以集群方式部署，并可针对部分结点进行硬件及软件扩容，具有一定的伸缩能力。 

3、共享性：每个部分都可以作为共享资源对外提供服务，多个部分可能有操作共享资源的情况。 

4、开放性：每个部分根据需求都可以对外发布共享资源的访问接口，并可允许第三方系统访问。

#### 2.2 分布式认证需求

分布式系统的每个服务都会有认证、授权的需求，如果每个服务都实现一套认证授权逻辑会非常冗余，考虑分布式 系统共享性的特点，需要由独立的认证服务处理系统认证授权的请求；考虑分布式系统开放性的特点，不仅对系统 内部服务提供认证，对第三方系统也要提供认证。分布式认证的需求总结如下：

**统一认证授权**

提供独立的认证服务，统一处理认证授权。

无论是不同类型的用户，还是不同种类的客户端(web端，H5、APP)，均采用一致的认证、权限、会话机制，实现 统一认证授权。

要实现统一则认证方式必须可扩展，支持各种认证需求，比如：用户名密码认证、短信验证码、二维码、人脸识别 等认证方式，并可以非常灵活的切换。

**应用接入认证**

应提供扩展和开放能力，提供安全的系统对接机制，并可开放部分API给接入第三方使用，一方应用（内部 系统服 务）和三方应用（第三方应用）均采用统一机制接入。

#### 2.3 分布式认证方案

##### 2.3.1 选型分析

1、基于session的认证方式 

在分布式的环境下，基于session的认证会出现一个问题，每个应用服务都需要在session中存储用户身份信息，通 过负载均衡将本地的请求分配到另一个应用服务需要将session信息带过去，否则会重新认证。

这个时候，通常的做法有下面几种： 

**Session复制**：多台应用服务器之间同步session，使session保持一致，对外透明。 

**Session黏贴**：当用户访问集群中某台服务器后，强制指定后续所有请求均落到此机器上。 

**Session集中存储**：将Session存入分布式缓存中，所有服务器应用实例统一从分布式缓存中存取Session。 

总体来讲，基于session认证的认证方式，可以更好的在服务端对会话进行控制，且安全性较高。但是，session机 制方式基于cookie，在复杂多样的移动客户端上不能有效的使用，并且无法跨域，另外随着系统的扩展需提高 session的复制、黏贴及存储的容错性。

2、基于token的认证方式

基于token的认证方式，服务端不用存储认证数据，易维护扩展性强， 客户端可以把token 存在任意地方，并且可 以实现web和app统一认证机制。其缺点也很明显，token由于自包含信息，因此一般数据量较大，而且每次请求 都需要传递，因此比较占带宽。另外，token的签名验签操作也会给cpu带来额外的处理负担。

##### 2.3.2 技术方案

根据 选型的分析，决定采用基于token的认证方式，它的优点是： 

1、适合统一认证的机制，客户端、一方应用、三方应用都遵循一致的认证机制。 

2、token认证方式对第三方应用接入更适合，因为它更开放，可使用当前有流行的开放协议Oauth2.0、JWT等

3、一般情况服务端无需存储会话信息，减轻了服务端的压力。

分布式系统认证技术方案见下图：

流程描述： 

（1）用户通过接入方（应用）登录，接入方采取OAuth2.0方式在统一认证服务(UAA)中认证。 

（2）认证服务(UAA)调用验证该用户的身份是否合法，并获取用户权限信息。 

（3）认证服务(UAA)获取接入方权限信息，并验证接入方是否合法。 

（4）若登录用户以及接入方都合法，认证服务生成jwt令牌返回给接入方，其中jwt中包含了用户权限及接入方权 限。 

（5）后续，接入方携带jwt令牌对API网关内的微服务资源进行访问。 

（6）API网关对令牌解析、并验证接入方的权限是否能够访问本次请求的微服务。 

（7）如果接入方的权限没问题，API网关将原请求header中附加解析后的明文Token，并将请求转发至微服务。

（8）微服务收到请求，明文token中包含登录用户的身份和权限信息。因此后续微服务自己可以干两件事：1，用 户授权拦截（看当前用户是否有权访问该资源）2，将用户信息存储进当前线程上下文（有利于后续业务逻辑随时 获取当前用户信息） 

流程所涉及到UAA服务、API网关这三个组件职责如下：

**1）统一认证服务(UAA)** 

它承载了OAuth2.0接入方认证、登入用户的认证、授权以及生成令牌的职责，完成实际的用户认证、授权功能。

 **2）API网关** 

作为系统的唯一入口，API网关为接入方提供定制的API集合，它可能还具有其它职责，如身份验证、监控、负载均 衡、缓存等。API网关方式的核心要点是，所有的接入方和消费端都通过统一的网关接入微服务，在网关层处理所 有的非业务功能。

### 3 OAuth2

#### 3.1 OAuth2介绍

OAuth（开放授权）是一个开放标准，允许用户授权第三方应用访问他们存储在另外的服务提供者上的信息，而不 需要将用户名和密码提供给第三方应用或分享他们数据的所有内容。OAuth2.0是OAuth协议的延续版本，但不向 后兼容OAuth 1.0即完全废止了OAuth1.0。很多大公司如Google，Yahoo，Microsoft等都提供了OAUTH认证服 务，这些都足以说明OAUTH标准逐渐成为开放资源授权的标准。 

Oauth协议目前发展到2.0版本，1.0版本过于复杂，2.0版本已得到广泛应用。

参考：https://baike.baidu.com/item/oAuth/7153134?fr=aladdin 

Oauth协议：https://tools.ietf.org/html/rfc6749

OAauth2.0包括以下角色： 

1、客户端 

本身不存储资源，需要通过资源拥有者的授权去请求资源服务器的资源，比如：Android客户端、Web客户端（浏 览器端）、微信客户端等。 

2、资源拥有者 

通常为用户，也可以是应用程序，即该资源的拥有者。 

3、授权服务器（也称认证服务器）

用于服务提供商对资源拥有的身份进行认证、对访问资源进行授权，认证成功后会给客户端发放令牌 （access_token），作为客户端访问资源服务器的凭据。本例为微信的认证服务器。 

4、资源服务器 

存储资源的服务器，本例子为微信存储的用户信息。

现在还有一个问题，服务提供商能允许随便一个**客户端**就接入到它的**授权服务器**吗？答案是否定的，服务提供商会 给准入的接入方一个身份，用于接入时的凭据: 

**client_id**：客户端标识 **client_secret**：客户端秘钥 

因此，准确来说，**授权服务器**对两种OAuth2.0中的两个角色进行认证授权，分别是**资源拥有者**、**客户端**。

#### 3.2 Spring Security OAuth2

##### 3.2.1 环境介绍

Spring-Security-OAuth2是对OAuth2的一种实现，并且跟我们之前学习的Spring Security相辅相成，与Spring Cloud体系的集成也非常便利，接下来，我们需要对它进行学习，最终使用它来实现我们设计的分布式认证授权解 决方案。 

OAuth2.0的服务提供方涵盖两个服务，即授权服务 (Authorization Server，也叫认证服务) 和资源服务 (Resource Server)，使用 Spring Security OAuth2的时候你可以选择把它们在同一个应用程序中实现，也可以选择建立使用 同一个授权服务的多个资源服务。

**授权服务 (Authorization Server）**应包含对接入端以及登入用户的合法性进行验证并颁发token等功能，对令牌 的请求端点由 Spring MVC 控制器进行实现，下面是配置一个认证服务必须要实现的endpoints： 

* **AuthorizationEndpoint** 服务于认证请求。默认 URL： /oauth/authorize 。 

* **TokenEndpoint** 服务于访问令牌的请求。默认 URL： /oauth/token 。 

**资源服务 (Resource Server)**，应包含对资源的保护功能，对非法请求进行拦截，对请求中token进行解析鉴 权等，下面的过滤器用于实现 OAuth 2.0 资源服务： 

* OAuth2AuthenticationProcessingFilter用来对请求给出的身份令牌解析鉴权。 

本教程分别创建uaa授权服务（也可叫认证服务）和order订单资源服务。 认证流程如下： 1、客户端请求UAA授权服务进行认证。 2、认证通过后由UAA颁发令牌。 3、客户端携带令牌Token请求资源服务。

认证流程如下： 
1、客户端请求UAA授权服务进行认证。
2、认证通过后由UAA颁发令牌。
3、客户端携带令牌Token请求资源服务。

##### 3.2.2 授权服务器配置

###### 3.2.2.1 EnableAuthorizationServer

可以用 @EnableAuthorizationServer 注解并继承AuthorizationServerConfigurerAdapter来配置OAuth2.0 授权 服务器。 

在Config包下创建AuthorizationServer：

```Java
@Configuration 
@EnableAuthorizationServer 
public class AuthorizationServer extends AuthorizationServerConfigurerAdapter { 
    //略... 
}
```

AuthorizationServerConfigurerAdapter要求配置以下几个类，这几个类是由Spring创建的独立的配置对象，它们 会被Spring传入AuthorizationServerConfigurer中进行配置。

```Java
public class AuthorizationServerConfigurerAdapter implements AuthorizationServerConfigurer { 
    public AuthorizationServerConfigurerAdapter() {} 
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {} 
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {} 		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {} 
}
```

* **ClientDetailsServiceConfigurer**：用来配置客户端详情服务（ClientDetailsService），客户端详情信息在 这里进行初始化，你能够把客户端详情信息写死在这里或者是通过数据库来存储调取详情信息。 
* **AuthorizationServerEndpointsConfigurer**：用来配置令牌（token）的访问端点和令牌服务(token services)。 
* **AuthorizationServerSecurityConfigurer**：用来配置令牌端点的安全约束.

###### 3.2.2.2 配置客户端详细信息

ClientDetailsServiceConfigurer 能够使用内存或者JDBC来实现客户端详情服务（ClientDetailsService）， ClientDetailsService负责查找ClientDetails，而ClientDetails有几个重要的属性如下列表：

* clientId：（必须的）用来标识客户的Id。 
* secret：（需要值得信任的客户端）客户端安全码，如果有的话。
* scope：用来限制客户端的访问范围，如果为空（默认）的话，那么客户端拥有全部的访问范围。
* authorizedGrantTypes：此客户端可以使用的授权类型，默认为空。
*  authorities：此客户端可以使用的权限（基于Spring Security authorities）。

客户端详情（Client Details）能够在应用程序运行的时候进行更新，可以通过访问底层的存储服务（例如将客户 端详情存储在一个关系数据库的表中，就可以使用 JdbcClientDetailsService）或者通过自己实现 ClientRegistrationService接口（同时你也可以实现 ClientDetailsService 接口）来进行管理。

###### 3.2.2.3 管理令牌

AuthorizationServerTokenServices 接口定义了一些操作使得你可以对令牌进行一些必要的管理，令牌可以被用来 加载身份信息，里面包含了这个令牌的相关权限。 

自己可以创建 AuthorizationServerTokenServices 这个接口的实现，则需要继承 DefaultTokenServices 这个类， 里面包含了一些有用实现，你可以使用它来修改令牌的格式和令牌的存储。默认的，当它尝试创建一个令牌的时 候，是使用随机值来进行填充的，除了持久化令牌是委托一个 TokenStore 接口来实现以外，这个类几乎帮你做了 所有的事情。并且 TokenStore 这个接口有一个默认的实现，它就是 InMemoryTokenStore ，如其命名，所有的 令牌是被保存在了内存中。除了使用这个类以外，你还可以使用一些其他的预定义实现，下面有几个版本，它们都 实现了TokenStore接口：

* InMemoryTokenStore：这个版本的实现是被默认采用的，它可以完美的工作在单服务器上（即访问并发量 压力不大的情况下，并且它在失败的时候不会进行备份），大多数的项目都可以使用这个版本的实现来进行 尝试，你可以在开发的时候使用它来进行管理，因为不会被保存到磁盘中，所以更易于调试。 

* JdbcTokenStore：这是一个基于JDBC的实现版本，令牌会被保存进关系型数据库。使用这个版本的实现时， 你可以在不同的服务器之间共享令牌信息，使用这个版本的时候请注意把"spring-jdbc"这个依赖加入到你的 classpath当中。 

* JwtTokenStore：这个版本的全称是 JSON Web Token（JWT），它可以把令牌相关的数据进行编码（因此对 于后端服务来说，它不需要进行存储，这将是一个重大优势），但是它有一个缺点，那就是撤销一个已经授 权令牌将会非常困难，所以它通常用来处理一个生命周期较短的令牌以及撤销刷新令牌（refresh_token）。 另外一个缺点就是这个令牌占用的空间会比较大，如果你加入了比较多用户凭证信息。JwtTokenStore 不会保存任何数据，但是它在转换令牌值以及授权信息方面与 DefaultTokenServices 所扮演的角色是一样的。

###### 3.2.2.4 令牌访问端点配置

  AuthorizationServerEndpointsConfigurer 这个对象的实例可以完成令牌服务以及令牌endpoint配置。

  **配置授权类型（Grant Types）**

  AuthorizationServerEndpointsConfigurer 通过设定以下属性决定支持的**授权类型（Grant Types）**:

  * authenticationManager：认证管理器，当你选择了资源所有者密码（password）授权类型的时候，请设置 这个属性注入一个 AuthenticationManager 对象。 
  * userDetailsService：如果你设置了这个属性的话，那说明你有一个自己的 UserDetailsService 接口的实现， 或者你可以把这个东西设置到全局域上面去（例如 GlobalAuthenticationManagerConfigurer 这个配置对 象），当你设置了这个之后，那么 "refresh_token" 即刷新令牌授权类型模式的流程中就会包含一个检查，用 来确保这个账号是否仍然有效，假如说你禁用了这个账户的话。
  * authorizationCodeServices：这个属性是用来设置授权码服务的（即 AuthorizationCodeServices 的实例对 象），主要用于 "authorization_code" 授权码类型模式。 implicitGrantService：这个属性用于设置隐式授权模式，用来管理隐式授权模式的状态。
  *  tokenGranter：当你设置了这个东西（即 TokenGranter 接口实现），那么授权将会交由你来完全掌控，并 且会忽略掉上面的这几个属性，这个属性一般是用作拓展用途的，即标准的四种授权模式已经满足不了你的 需求的时候，才会考虑使用这个。

**配置授权端点的URL（Endpoint URLs）**：

AuthorizationServerEndpointsConfigurer 这个配置对象有一个叫做 pathMapping() 的方法用来配置端点URL链 接，它有两个参数： 

* 第一个参数：String 类型的，这个端点URL的默认链接。 
* 第二个参数：String 类型的，你要进行替代的URL链接。

以上的参数都将以 "/" 字符为开始的字符串，框架的默认URL链接如下列表，可以作为这个 pathMapping() 方法的 第一个参数：

* /oauth/authorize：授权端点。 
* /oauth/token：令牌端点。 
* /oauth/confirm_access：用户确认授权提交端点。 
* /oauth/error：授权服务错误信息端点。 
* /oauth/check_token：用于资源服务访问的令牌解析端点。 
* /oauth/token_key：提供公有密匙的端点，如果你使用JWT令牌的话。

需要注意的是授权端点这个URL应该被Spring Security保护起来只供授权用户访问.

###### 3.2.2.5 令牌端点的安全约束

**AuthorizationServerSecurityConfigurer**：用来配置令牌端点(Token Endpoint)的安全约束，在 AuthorizationServer中配置如下.

```Java
@Override 
public void configure(AuthorizationServerSecurityConfigurer security){ 
    security .tokenKeyAccess("permitAll()") (1) 
        .checkTokenAccess("permitAll()") (2) 
        .allowFormAuthenticationForClients() (3) ; 
}
```

（1）tokenkey这个endpoint当使用JwtToken且使用非对称加密时，资源服务用于获取公钥而开放的，这里指这个 endpoint完全公开。 

（2）checkToken这个endpoint完全公开 

（3） 允许表单认证

**授权服务配置总结**：授权服务配置分成三大块，可以关联记忆。 

既然要完成认证，它首先得知道客户端信息从哪儿读取，因此要进行客户端详情配置。 

既然要颁发token，那必须得定义token的相关endpoint，以及token如何存取，以及客户端支持哪些类型的 token。 

既然暴露除了一些endpoint，那对这些endpoint可以定义一些安全上的约束等。

##### 3.2.3 授权码模式

###### 3.2.3.1 授权码模式介绍

（1）**资源拥有者打开客户端，客户端要求资源拥有者给予授权，它将浏览器被重定向到授权服务器，重定向时会 附加客户端的身份信息。如：**

```http
/uaa/oauth/authorize?client_id=c1&response_type=code&scope=all&redirect_uri=http://www.baidu.com
```

参数列表如下： 

* client_id：客户端准入标识。 
* response_type：授权码模式固定为code。 
* scope：客户端权限。 
* redirect_uri：跳转uri，当授权码申请成功后会跳转到此地址，并在后边带上code参数（授权码）。

**（2）浏览器出现向授权服务器授权页面，之后将用户同意授权。**

**（3）授权服务器将授权码（AuthorizationCode）转经浏览器发送给client(通过redirect_uri)。** 

**（4）客户端拿着授权码向授权服务器索要访问access_token，请求如下：**

```Http
/uaa/oauth/token? client_id=c1&client_secret=secret&grant_type=authorization_code&code=5PgfcD&redirect_uri=http://www.baidu.com
```

参数列表如下 

* client_id：客户端准入标识。
*  client_secret：客户端秘钥。 
* grant_type：授权类型，填写authorization_code，表示授权码模式 
* code：授权码，就是刚刚获取的授权码，注意：授权码只使用一次就无效了，需要重新申请。 
* redirect_uri：申请授权码时的跳转url，一定和申请授权码时用的redirect_uri一致。

**（5）授权服务器返回令牌(access_token)**

##### 3.2.4 简化模式

###### 3.2.4.1 简化模式介绍

**（1）资源拥有者打开客户端，客户端要求资源拥有者给予授权，它将浏览器被重定向到授权服务器，重定向时会 附加客户端的身份信息。如：**

```Http
/uaa/oauth/authorize?client_id=c1&response_type=token&scope=all&redirect_uri=http://www.baidu.com
```

参数描述同授权码模式 ，注意**response_type=token**，说明是简化模式。

**（2）浏览器出现向授权服务器授权页面，之后将用户同意授权。** 

**（3）授权服务器将授权码将令牌（access_token）以Hash的形式存放在重定向uri的fargment中发送给浏览器。**

注：fragment 主要是用来标识 URI 所标识资源里的某个资源，在 URI 的末尾通过 （#）作为 fragment 的开头， 其中 # 不属于 fragment 的值。如https://domain/index#L18这个 URI 中 L18 就是 fragment 的值。大家只需要 知道js通过响应浏览器地址栏变化的方式能获取到fragment 就行了。 

一般来说，简化模式用于没有服务器端的第三方单页面应用，因为没有服务器端就无法接收授权码。

##### 3.2.5 密码模式

###### 3.2.5.1 授权码模式介绍

**（1）资源拥有者将用户名、密码发送给客户端** 

**（2）客户端拿着资源拥有者的用户名、密码向授权服务器请求令牌（access_token）**，请求如下：

```http
/uaa/oauth/token? client_id=c1&client_secret=secret&grant_type=password&username=shangsan&password=123
```

参数列表如下： 

* client_id：客户端准入标识。 
* client_secret：客户端秘钥。 
* grant_type：授权类型，填写password表示密码模式 
* username：资源拥有者用户名。 
* password：资源拥有者密码。

**（3）授权服务器将令牌（access_token）发送给client**

这种模式十分简单，但是却意味着直接将用户敏感信息泄漏给了client，因此这就说明这种模式只能用于client是我 们自己开发的情况下。因此密码模式一般用于我们自己开发的，第一方原生App或第一方单页面应用。

##### 3.2.6 客户端模式

###### 3.2.6.1 客户端模式介绍

**（1）客户端向授权服务器发送自己的身份信息，并请求令牌（access_token）** 

**（2）确认客户端身份无误后，将令牌（access_token）发送给client**，请求如下：

```http
/uaa/oauth/token?client_id=c1&client_secret=secret&grant_type=client_credentials
```

参数列表如下： 

* client_id：客户端准入标识。 
* client_secret：客户端秘钥。 
* grant_type：授权类型，填写client_credentials表示客户端模式 

这种模式是最方便但最不安全的模式。因此这就要求我们对client完全的信任，而client本身也是安全的。因 此这种模式一般用来提供给我们完全信任的服务器端服务。比如，合作方系统对接，拉取一组用户信息。

##### 3.2.7 资源服务器配置

###### 3.2.7.1 资源服务器配置

@EnableResourceServer 注解到一个 @Configuration 配置类上，并且必须使用 ResourceServerConfigurer 这个 配置对象来进行配置（可以选择继承自 ResourceServerConfigurerAdapter 然后覆写其中的方法，参数就是这个 对象的实例），下面是一些可以配置的属性： 

ResourceServerSecurityConfigurer中主要包括：

* tokenServices：ResourceServerTokenServices 类的实例，用来实现令牌服务。 
* tokenStore：TokenStore类的实例，指定令牌如何访问，与tokenServices配置可选 
* resourceId：这个资源服务的ID，这个属性是可选的，但是推荐设置并在授权服务中进行验证。 
* 其他的拓展属性例如 tokenExtractor 令牌提取器用来提取请求中的令牌。

HttpSecurity配置这个与Spring Security类似：

* 请求匹配器，用来设置需要进行保护的资源路径，默认的情况下是保护资源服务的全部路径。 
* 通过http.authorizeRequests()来设置受保护资源的访问规则 
* 其他的自定义权限保护规则通过 HttpSecurity 来进行配置。

@EnableResourceServer 注解自动增加了一个类型为 OAuth2AuthenticationProcessingFilter 的过滤器链

###### 3.2.7.2 验证Token

ResourceServerTokenServices 是组成授权服务的另一半，如果你的授权服务和资源服务在同一个应用程序上的 话，你可以使用 DefaultTokenServices ，这样的话，你就不用考虑关于实现所有必要的接口的一致性问题。如果 你的资源服务器是分离开的，那么你就必须要确保能够有匹配授权服务提供的 ResourceServerTokenServices，它 知道如何对令牌进行解码。

令牌解析方法： 使用 DefaultTokenServices 在资源服务器本地配置令牌存储、解码、解析方式 使用 RemoteTokenServices 资源服务器通过 HTTP 请求来解码令牌，每次都请求授权服务器端点 /oauth/check_token

使用授权服务的 /oauth/check_token 端点你需要在授权服务将这个端点暴露出去，以便资源服务可以进行访问。

#### 3.3 JWT令牌

##### 3.3.1 JWT令牌介绍

当资源服务和授权服务不在一起时资源服务使用RemoteTokenServices 远程请求授权 服务验证token，如果访问量较大将会影响系统的性能 。 

解决上边问题： 

令牌采用JWT格式即可解决上边的问题，用户认证通过会得到一个JWT令牌，JWT令牌中已经包括了用户相关的信 息，客户端只需要携带JWT访问资源服务，资源服务根据事先约定的算法自行完成令牌校验，无需每次都请求认证 服务完成授权。 

**1、什么是JWT？**

JSON Web Token（JWT）是一个开放的行业标准（RFC 7519），它定义了一种简介的、自包含的协议格式，用于 在通信双方传递json对象，传递的信息经过数字签名可以被验证和信任。JWT可以使用HMAC算法或使用RSA的公 钥/私钥对来签名，防止被篡改。 

官网：https://jwt.io/ 

标准：https://tools.ietf.org/html/rfc7519

JWT令牌的优点： 

1）jwt基于json，非常方便解析。 

2）可以在令牌中自定义丰富的内容，易扩展。 

3）通过非对称加密算法及数字签名技术，JWT防止篡改，安全性高。 

4）资源服务使用JWT可不依赖认证服务即可完成授权。

缺点： 

１）JWT令牌较长，占存储空间比较大。

**2、JWT令牌结构**

通过学习JWT令牌结构为自定义jwt令牌打好基础。 

JWT令牌由三部分组成，每部分中间使用点（.）分隔，比如：xxxxx.yyyyy.zzzzz

* Header

  头部包括令牌的类型（即JWT）及使用的哈希算法（如HMAC SHA256或RSA） 

  一个例子如下： 

  下边是Header部分的内容

```Json
{ 
    "alg": "HS256", 
    "typ": "JWT" 
}
```

将上边的内容使用Base64Url编码，得到一个字符串就是JWT令牌的第一部分。

* Payload

  第二部分是负载，内容也是一个json对象，它是存放有效信息的地方，它可以存放jwt提供的现成字段，比 如：iss（签发者）,exp（过期时间戳）, sub（面向的用户）等，也可自定义字段。 

  此部分不建议存放敏感信息，因为此部分可以解码还原原始内容。 

  最后将第二部分负载使用Base64Url编码，得到一个字符串就是JWT令牌的第二部分。 一个例子：

```json
{ 
    "sub": "1234567890", 
    "name": "456", 
    "admin": true 
}
```

* Signature

  第三部分是签名，此部分用于防止jwt内容被篡改。 

  这个部分使用base64url将前两部分进行编码，编码后使用点（.）连接组成字符串，最后使用header中声明 签名算法进行签名。 

  一个例子：

  ```java
  HMACSHA256( 
  	base64UrlEncode(header) + "." + 
  	base64UrlEncode(payload), 
  	secret
  )
  ```

  base64UrlEncode(header)：jwt令牌的第一部分。 

  base64UrlEncode(payload)：jwt令牌的第二部分。 

  secret：签名所使用的密钥。

  (页码93). 