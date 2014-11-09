package org.springframework.security.acls.neo4j.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.acls.domain.AclAuthorizationStrategy;
import org.springframework.security.acls.jdbc.BasicLookupStrategy;
import org.springframework.security.acls.jdbc.JdbcMutableAclService;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.PermissionGrantingStrategy;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;
import org.springframework.transaction.config.JtaTransactionManagerFactoryBean;

@Configuration
@ComponentScan(basePackages = { "org.springframework.security.acls.neo4j" })
@Profile(value="dev-h2")
@EnableTransactionManagement
public class H2TestConfig {
	
	@Autowired
	private AclCache aclCache;
	
	@Autowired
	private AclAuthorizationStrategy aclAuthorizationStrategy;
	
	@Autowired
	private PermissionGrantingStrategy permissionGrantingStrategy;
	
	@Bean
	public DataSource dataSource() {
		return new EmbeddedDatabaseBuilder().setType(EmbeddedDatabaseType.H2)
				.addScript("META-INF/h2-security-acl-schema.sql").build();
	}	

	@Bean
	public LookupStrategy lookupStrategy() {
		return new BasicLookupStrategy(dataSource(), aclCache,
				aclAuthorizationStrategy, permissionGrantingStrategy);
	}

	@Bean
	public MutableAclService MutableAclService() {
		return new JdbcMutableAclService(dataSource(), lookupStrategy(),
				aclCache);
	}
	
	@Bean
	public PlatformTransactionManager transactionManager() {
		JtaTransactionManagerFactoryBean jtaTransactionManagerFactoryBean = new JtaTransactionManagerFactoryBean();
		return jtaTransactionManagerFactoryBean.getObject();
	}
}
