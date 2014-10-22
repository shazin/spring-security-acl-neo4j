package org.springframework.security.acls.neo4j;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.Arrays;
import java.util.Map;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Permission;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.neo4j.config.AppTestConfig;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

@ContextConfiguration(classes={AppTestConfig.class})
@RunWith(SpringJUnit4ClassRunner.class)
@Transactional(readOnly=true)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
public class Neo4jAclServiceTest {

	@Autowired
	private MutableAclService mutableAclService;	
	
	@Test
	@Rollback(false)
	@Transactional(rollbackFor=Exception.class)
	public void test1readAclById() {
		Authentication auth = new TestingAuthenticationToken("shazin", "N/A");
		auth.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(auth);
		for(int i=1;i<=100;i++) {
			ObjectIdentity oid = new ObjectIdentityImpl(String.format("com.test.Shazin%d", i), Long.valueOf(i));
			
			MutableAcl acl = mutableAclService.createAcl(oid);
		}
		
		ObjectIdentity oid = new ObjectIdentityImpl("com.test.Shazin50", 50l);
		
		
		long start = System.nanoTime();
		MutableAcl acl = (MutableAcl) mutableAclService.readAclById(oid);
		long end = System.nanoTime();
		System.out.println("Time to Read "+(end - start));
		assertNotNull(acl);
		
	}
	
	@Test
	@Rollback(false)
	@Transactional(rollbackFor=Exception.class)
	public void test2readAclsById() {
		Authentication auth = new TestingAuthenticationToken("shazin", "N/A");
		auth.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(auth);
		
		for(int i=1;i<=100;i++) {
			ObjectIdentity oid = new ObjectIdentityImpl(String.format("com.test.Shazin%d", i), Long.valueOf(i));
			
			MutableAcl acl = (MutableAcl) mutableAclService.readAclById(oid);
			
			for(int j=0;j<2;j++) {
				Permission permission = null;
				Sid sid = null;
				boolean granting = true;
				if(j % 2 == 0) {
					permission = BasePermission.CREATE;
					sid = new PrincipalSid(String.format("USER_%d", j));						
				} else {
					permission = BasePermission.DELETE;
					sid = new GrantedAuthoritySid(String.format("ROLE_%d", j));
				}
				acl.insertAce(j, permission, sid, granting);
			}
			
			mutableAclService.updateAcl(acl);
		}
		
		long start = System.nanoTime();		
		Map<ObjectIdentity, Acl> objects = mutableAclService.readAclsById(Arrays.<ObjectIdentity>asList(new ObjectIdentityImpl("com.test.Shazin99", 99l), new ObjectIdentityImpl("com.test.Shazin98", 98l)));
		long end = System.nanoTime();
		
		assertEquals(2, objects.size());
		for(Map.Entry<ObjectIdentity, Acl> entry:objects.entrySet()) {
			assertEquals(2, entry.getValue().getEntries().size());
		}
	}

	
}
