# Authentication-and-Authorization-SpringSecurity
notes from: https://medium.com/@minadev/authentication-and-authorization-with-spring-security-bf22e985f2cb     and  https://dev.to/m1guelsb/authentication-and-authorization-with-spring-boot-4m2n

## Authentication Mechnisms:
There are two authentication mechanisms: stateful and stateless.

#### Stateful Authentication (Cookie/Session Based Authentication):

This is the default and traditional method for handling user authentication. In this approach, the backend is responsible for creating, storing the session ID, and verifying the user’s identity.
Here is how it works: The server creates a session ID upon a user’s login request, storing it in either a database or an in-memory cache on the server. This session ID is then stored on a cookie in the user’s browser. With each subsequent request, the server receives the cookie containing the session ID and validates the user’s identity by comparing it with the corresponding session information stored on the server.
![0 bejurH3uZoTrZita](https://github.com/SDguyleroc/Authentication-and-Authorization-SpringSecurity/assets/126127721/534d35df-1374-480b-8b79-2648d1beb603)

##### Stateful disadvantages:

Scalability: This approach might have challenges in highly scalable systems, as it requires server-side storage for session data.

Complexity: Implementing and managing session data, can add complexity to the system.

## Stateless Authentication:
Stateless authentication using tokens (.eg, JWT) that are gaining popularity, especially in modern Microservices and distributed systems.

##### Token-based Authentication:
Issuing a token (JWT) upon successful authentication. The token is sent to the server with each request authorization.
It is Stateless and scalable.

![stateless-Cloud-Secret-Double-Octopus-1](https://github.com/SDguyleroc/Authentication-and-Authorization-SpringSecurity/assets/126127721/42b63630-04df-42d1-a191-a1cbae1fab28)

#### Json Web Token(JWT)
JWT represents claims between two parties. JWT has a compact format, making them easy to transform over the network.

![0 vDqf2sG-wYdj7lC9](https://github.com/SDguyleroc/Authentication-and-Authorization-SpringSecurity/assets/126127721/21c82823-b09c-44d4-9680-68487ced4bf1)

It consists of three parts: 
* #### Header:
  Specifies the JWT encoding and signing algorithm, with properties { "alg": "HS256", "typ": "jWT"} where alg is the algorithm that is used to encrypt the JWT.

 * ### PayLoad:
   Contains the data(Claims) to be sent as jSon property-value pairs within the claims.
* ### This is created by encrypting, with the algorithm specified in the header: (i) the base64Url-encoded, (ii) base64Url-encoded payload, and (iii) a secret (or a private key):

HMACSHA256(
  base64UrlEncode(header) + "." + 
  base64UrlEncode(payload), 
  secret|privateKey)
Where and why should we use JWT?

Authentication: JWTs can be used for user authentication. Once a user logs in, a JWT is generated on the server and sent to the client. The client includes this token in the header of subsequent requests to authenticate the user.

Stateless: JWTs are often used in stateless authentication mechanisms. The server does not need to store the user’s session data, making it scalable, efficient and less complex.

Expiration: JWTs can have an expiration time, after which they are no longer considered valid. This helps enhance security by limiting the window of opportunity for an attacker to use a stolen token.


Adding spring security, enables us with the security filter chain to process requests and perform security-related tasks. We can customize this filter chain by adding or modifying filters based on our requirements.

This ensures that any incoming request will go through these filters.

![unnamed](https://github.com/SDguyleroc/Authentication-and-Authorization-SpringSecurity/assets/126127721/e42409f7-abc0-4db0-b179-4d199a807a67)

# Project set up

We'll be using the following technologies:

    Java 17
    Spring-boot 3.1.5
    jwt
    hibernate/jpa
    postgresql
    lombok
Summary
*  First steps
*  User entity and repository
*  Token provider
*  Security filter
*  Auth configuration
*  Auth DTOs
*  Auth service
*  Auth controller
*  Testing the authentication

code source: https://github.com/m1guelsb/spring-auth

* There are two depencies we need in our pom.xml to protect our application.

* spring native security package  and ath0 which will help us create and valid our jwt tokens
```
//pom.xml
<dependency>
   <groupId>org.springframework.boot</groupId>
   <artifactId>spring-boot-starter-security</artifactId>
</dependency>

<dependency>
   <groupId>com.auth0</groupId>
   <artifactId>java-jwt</artifactId>
   <version>4.4.0</version>
</dependency>
```

## user Entity and repository

to represent user roles we need enum to help us define the permissions of each user in our application.

```java
// enums/UserRole.java
public enum UserRole {
  ADMIN("admin"),
  USER("user");

  private String role;

  UserRole(String role) {
    this.role = role;
  }

  public String getValue() {
    return role;
  }
}
```

* we have two representative roles: ADMIN and USER
* the ADMIN role will have access to all our enpoints
*  while USER role will only have access to specific endpoints.

The user entity will be the core of our authentication system, it will hold the user's credentials and the roles that user has. We'll be implementing the userDetails interface to represent our user entity, which is provided by the spring security package and it;s the recommended way to represent the user entity in a spring-boot application.

```java
  // entities/UserEntity.java
@Table()
@Entity(name = "users")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(of = "id")
public class User implements UserDetails {

  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Long id;

  private String login;

  private String password;

  @Enumerated(EnumType.STRING)
  private UserRole role;

  public User(String login, String password, UserRole role) {
    this.login = login;
    this.password = password;
    this.role = role;
  }

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    if (this.role == UserRole.ADMIN) {
      return List.of(new SimpleGrantedAuthority("ROLE_ADMIN"), new SimpleGrantedAuthority("ROLE_USER"));
    }
    return List.of(new SimpleGrantedAuthority("ROLE_USER"));
  }

  @Override
  public String getUsername() {
    return login;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }
}
```

It has a lot of methods that we can override from userDetails to customize the authentication proccess, you can implement those properties in the database too but for now we'll only use the required to make our authentication system work: id, username, passoword, and role.
for the user repository we have the following code:
```java

// repositories/UserRepository.java
public interface UserRepository extends JpaRepository<User, Long> {
  UserDetails findByLogin(String login);
}
```
Extending the JpaRepository we'll have access to a lot of methods to manipulate our users in the database. In addition, the findByLogin method will be used by the spring security to find the user in the database and validate the credentials.

### Token provider

We need to define a secrete key to sign our tokens, this key will be used to validate and to generate the token signature. we'll be using the @Value annotation to get the secrete key from the application.yml file. And in the application.yml file we'll define the secrete key as an enviroment variable, this will help us keep the secrete key safe and out of the source code.

```
//.env
JWT_SECRET="yoursecret"
```

In our application.yml:

```yml
// resources/application.yml
security:
  jwt:
    token:
      secret-key: ${JWT_SECRET}
```

To the spring-boot application read the environment variables we need declare the PropertySource annotation in our main class indicating where is the .env file located. In our case it's located in the root of the project, so we'll use the user.dir variable to get the project root path. The main class will look like this:
```java
@SpringBootApplication
@PropertySource("file:${user.dir}/.env")
public class SpringAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringAuthApplication.class, args);
    }
}
```

finally we can define our token provider class, this class will be responsible to generate and validate our tokens.
```java
// config/auth/TokenProvider.java
@Service
public class TokenProvider {
  @Value("${security.jwt.token.secret-key}")
  private String JWT_SECRET;

  public String generateAccessToken(User user) {
    try {
      Algorithm algorithm = Algorithm.HMAC256(JWT_SECRET);
      return JWT.create()
          .withSubject(user.getUsername())
          .withClaim("username", user.getUsername())
          .withExpiresAt(genAccessExpirationDate())
          .sign(algorithm);
    } catch (JWTCreationException exception) {
      throw new JWTCreationException("Error while generating token", exception);
    }
  }

  public String validateToken(String token) {
    try {
      Algorithm algorithm = Algorithm.HMAC256(JWT_SECRET);
      return JWT.require(algorithm)
          .build()
          .verify(token)
          .getSubject();
    } catch (JWTVerificationException exception) {
      throw new JWTVerificationException("Error while validating token", exception);
    }
  }

  private Instant genAccessExpirationDate() {
    return LocalDateTime.now().plusHours(2).toInstant(ZoneOffset.of("-03:00"));
  }
}
```

In the generateAccessToken we define an algorithm to sign our token, the subject of the token and the expiration date and return a new token. In the validateToken method we validate the token signature and return the subject of the token.

## Securoty filter

```java
// config/auth/SecurityFilter.java
@Component
public class SecurityFilter extends OncePerRequestFilter {
  @Autowired
  TokenProvider tokenService;
  @Autowired
  UserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    var token = this.recoverToken(request);
    if (token != null) {
      var login = tokenService.validateToken(token);
      var user = userRepository.findByLogin(login);
      var authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
      SecurityContextHolder.getContext().setAuthentication(authentication);
    }
    filterChain.doFilter(request, response);
  }

  private String recoverToken(HttpServletRequest request) {
    var authHeader = request.getHeader("Authorization");
    if (authHeader == null)
      return null;
    return authHeader.replace("Bearer ", "");
  }
}
```

In the doFilterInternal method we recover the token from the request, remove the "Bearer" from the string using the recoverToken helper method, validate the token and set the authentication in the SecurityContextHolder. The SecurityContextHolder is a spring security class that holds the authentication of the current request, so we can access the user information in the controllers.



## Auth configuration

Here we need to define some more necessary methods to make our authentication system work. At the top we have the configuration and @EnableWebSecurity annotation to enable the web security in our application. Then we define the SecurityFilterChain bean to define the endpoints that will be protected by our authentication system.

```java
// config/AuthConfig.java
@Configuration
@EnableWebSecurity
public class AuthConfig {
  @Autowired
  SecurityFilter securityFilter;

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
    return httpSecurity
        .csrf(csrf -> csrf.disable())
        .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .authorizeHttpRequests(authorize -> authorize
            .requestMatchers(HttpMethod.POST, "/api/v1/auth/*").permitAll()
            .requestMatchers(HttpMethod.POST, "/api/v1/books").hasRole("ADMIN")
            .anyRequest().authenticated())
        .addFilterBefore(securityFilter, UsernamePasswordAuthenticationFilter.class)
        .build();
  }

  @Bean
  AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
      throws Exception {
    return authenticationConfiguration.getAuthenticationManager();
  }

  @Bean
  PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }
}

```

In the authorizeHttpRequests method we define the endpoints that will be protected and the roles that will have access to each endpoint. In our case the /api/v1/auth/* endpoints will be public, the /api/v1/books endpoint will be protected and only the users with the ADMIN role will have access to it. The others endpoints will be protected and only the authenticated users will have access to it.

In the addFilterBefore method we define the filter that we created before. And finally we define the AuthenticationManager and the PasswordEncoder beans that is necessary to make the authentication system work.

In the addFilterBefore method we define the filter that we created before. And finally we define the AuthenticationManager and the PasswordEncoder beans that is necessary to make the authentication system work.

#Auth DTOs

We'll need two DTO's to receive the user credentials, and another DTO to return the token when user sign in.
```java
// dtos/SignUpDto.java
public record SignUpDto(
    String login,
    String password,
    UserRole role) {
}
```
```java

// dtos/SignInDto.java
public record SignInDto(
    String login,
    String password) {
}
```
```java

// dtos/JwtDto.java
public record JwtDto(
    String accessToken) {
}
```
### Auth service

here we define the service implementing UserdetailsService that will be responsible to create the the users and save them in the database or load the user information by the username.

```java
// services/AuthService.java
@Service
public class AuthService implements UserDetailsService {

  @Autowired
  UserRepository repository;

  @Override
  public UserDetails loadUserByUsername(String username) {
    var user = repository.findByLogin(username);
    return user;
  }

  public UserDetails signUp(SignUpDto data) throws InvalidJwtException {
    if (repository.findByLogin(data.login()) != null) {
      throw new InvalidJwtException("Username already exists");
    }
    String encryptedPassword = new BCryptPasswordEncoder().encode(data.password());
    User newUser = new User(data.login(), encryptedPassword, data.role());
    return repository.save(newUser);
  }
}


```
In the signUp method we check if the username is already registered then encrypt the password using the BCryptPassowrdEncorder and save the user information.


Auth controller

And finally we define the auth controller. It will be responsible to receive the request, authenticate the users and generate the tokens.

```java
// controllers/AuthController.java
@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
  @Autowired
  private AuthenticationManager authenticationManager;
  @Autowired
  private AuthService service;
  @Autowired
  private TokenProvider tokenService;

  @PostMapping("/signup")
  public ResponseEntity<?> signUp(@RequestBody @Valid SignUpDto data) {
    service.signUp(data);
    return ResponseEntity.status(HttpStatus.CREATED).build();
  }

  @PostMapping("/signin")
  public ResponseEntity<JwtDto> signIn(@RequestBody @Valid SignInDto data) {
    var usernamePassword = new UsernamePasswordAuthenticationToken(data.login(), data.password());
    var authUser = authenticationManager.authenticate(usernamePassword);
    var accessToken = tokenService.generateAccessToken((User) authUser.getPrincipal());
    return ResponseEntity.ok(new JwtDto(accessToken));
  }
}

```

In the signUp method we receive the user data, create a new user and save it in the database. In the signIn method we receive the user credentials, authenticate the user using the AuthenticationManager, and generate the token.




Testing the authentication

To create a new user we send a POST request to the /api/v1/auth/signup endpoint with a body containing the login, password and one of the roles available (USER or ADMIN):
```
{
  "login": "myusername",
  "password": "123456",
  "role": "USER"
}
```

To retrieve an authentication token we send a POST request with this user login and password to the /api/v1/auth/signin endpoint.

To test our authentication system we'll create a simple book controller with two endpoints, one to create a new book and another one to list all the books.
```java
@RestController
@RequestMapping("/api/v1/books")
public class BookController {

  @GetMapping
  public ResponseEntity<List<String>> findAll() {
    return ResponseEntity.ok(List.of("Book1", "Book2", "Book3"));
  }

  @PostMapping
  public ResponseEntity<String> create(@RequestBody String data) {
    return ResponseEntity.ok(data);
  }
}
```

In the /api/v1/books endpoint the GET method will be available for the users with USER role, and the POST method will be protected and only the users with the ADMIN role will be able to create a book.








  



  
