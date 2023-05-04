
1) Step 1 : Add Depandancy 

	 <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>


	 <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.9.1</version>
        </dependency>
		
		
		// For XML Bind 
	
	 <dependency>
            <groupId>javax.xml.bind</groupId>
            <artifactId>jaxb-api</artifactId>
            <version>2.4.0-b180830.0359</version>
        </dependency>
		
		
2) Step 2 : Create Custom User details Class For load Username 


	@Service
	public class CustomUserDetailsService  implements UserDetailsService {

    @Autowired
    private UserRepo userRepo ;


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User useremail = this.userRepo.findByEmail(username).orElseThrow(() -> new ResourcenotfoundExaption("User", "Email " + username, 0));
        return useremail;
    }
}


3) Step 3 : Create JwtAuthEntryPoint Class

	@Component
	public class jwtauthenterypoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED,"Access Denied !");
    }
}


4) Step 4 : Create SecurityConfig Class 


	@Configuration
	@EnableWebSecurity
	@EnableMethodSecurity(prePostEnabled = true)
	public class SecurityConfig {
    @Autowired
    private CustomUserDetailsService userDetailsService ;

    @Autowired
    private JwtAuthFilter jwtAuthFilter ;

    @Autowired
    private jwtauthenterypoint jwtaenterypoint ;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       http.csrf()
             .disable()
             .authorizeHttpRequests().requestMatchers("/api/v1/auth/**").permitAll()
               .anyRequest().authenticated().
             and().exceptionHandling().authenticationEntryPoint(this.jwtaenterypoint).
             and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) ;
       http.addFilterBefore(this.jwtAuthFilter,UsernamePasswordAuthenticationFilter.class);

       http.authenticationProvider(provider());

        return http.build();

    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // return NoOpPasswordEncoder.getInstance();
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    @Bean
    public DaoAuthenticationProvider provider()
    {
    DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
    daoAuthenticationProvider.setUserDetailsService(this.userDetailsService);
    daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
    return  daoAuthenticationProvider;
    }
}


5) Step 5 : Create JwtHelper Class  

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    @Autowired
    private CustomUserDetailsService userDetailsService ;

    @Autowired
    private JwtAuthFilter jwtAuthFilter ;

    @Autowired
    private jwtauthenterypoint jwtaenterypoint ;
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
       http.csrf()
             .disable()
             .authorizeHttpRequests().requestMatchers("/api/v1/auth/**").permitAll()
               .anyRequest().authenticated().
             and().exceptionHandling().authenticationEntryPoint(this.jwtaenterypoint).
             and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) ;
       http.addFilterBefore(this.jwtAuthFilter,UsernamePasswordAuthenticationFilter.class);

       http.authenticationProvider(provider());

        return http.build();

    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // return NoOpPasswordEncoder.getInstance();
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }


    @Bean
    public DaoAuthenticationProvider provider()
    {
    DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
    daoAuthenticationProvider.setUserDetailsService(this.userDetailsService);
    daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
    return  daoAuthenticationProvider;
    }
}

6) Step 6 : Craete JwtTokenResponce Class For responce 

		@Data
	public class JwtResponce {

    private String Token;
    private Date ValidTill;
}


7) Step 7 : Create Auth Controller class


@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {
@Autowired
    private JwtHelper jwtHelper ;

@Autowired
private  UserDetailsService userDetailsService  ;

@Autowired
private AuthenticationManager authenticationManager ;
    @PostMapping("/login")
    public ResponseEntity<JwtResponce> createtoken(@RequestBody Authdto authdto )
    {
       this.authanticate(authdto.getUsername(),authdto.getPassword());
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(authdto.getUsername());
        String token = this.jwtHelper.generateToken(userDetails);
        Date tokenexp = this.jwtHelper.getExpirationDateFromToken(token);
        JwtResponce jwtResponce = new JwtResponce() ;
        jwtResponce.setToken(token);
        jwtResponce.setValidTill(tokenexp);
        return new ResponseEntity<>(jwtResponce, HttpStatus.OK);

    }

    private void authanticate(String username, String password) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username,password);
        Authentication authenticate = this.authenticationManager.authenticate(usernamePasswordAuthenticationToken);

    }
}
