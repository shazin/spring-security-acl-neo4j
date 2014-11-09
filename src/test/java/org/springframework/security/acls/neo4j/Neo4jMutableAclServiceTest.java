package org.springframework.security.acls.neo4j;

import static org.junit.Assert.assertEquals;

import org.junit.FixMethodOrder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.MethodSorters;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.acls.domain.BasePermission;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.neo4j.config.AppTestConfig;
import org.springframework.security.acls.neo4j.config.H2TestConfig;
import org.springframework.security.acls.neo4j.config.Neo4jTestConfig;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.transaction.annotation.Transactional;

@ContextConfiguration(classes = { AppTestConfig.class, H2TestConfig.class, Neo4jTestConfig.class })
@RunWith(SpringJUnit4ClassRunner.class)
@Transactional(readOnly = true)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
@ActiveProfiles(value="dev-neo4j")
public class Neo4jMutableAclServiceTest {

	@Autowired
	private MutableAclService mutableAclService;

	@Test
	@Rollback(false)
	@Transactional(rollbackFor = Exception.class)
	public void test1CreateAcl() {
		Authentication auth = new TestingAuthenticationToken("shazin", "N/A");
		auth.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(auth);
		ObjectIdentity oid = new ObjectIdentityImpl("my.test.Class", 1l);
		MutableAcl acl = mutableAclService.createAcl(oid);
	}

	@Test
	@Rollback(false)
	@Transactional(rollbackFor = Exception.class)
	public void test2UpdateAcl() {
		Authentication auth = new TestingAuthenticationToken("shazin", "N/A");
		auth.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(auth);
		ObjectIdentity oid = new ObjectIdentityImpl("my.test.Class", 1l);
		MutableAcl acl = (MutableAcl) mutableAclService.readAclById(oid);

		acl.insertAce(0, BasePermission.CREATE, new GrantedAuthoritySid(
				"ROLE_USER"), true);
		acl.insertAce(1, BasePermission.DELETE, new GrantedAuthoritySid(
				"ROLE_ADMIN"), true);

		mutableAclService.updateAcl(acl);
	}

	@Test(expected = NotFoundException.class)
	@Rollback(false)
	@Transactional(rollbackFor = Exception.class)
	public void test3DeleteAcl() {
		Authentication auth = new TestingAuthenticationToken("shazin", "N/A");
		auth.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(auth);
		ObjectIdentity oid = new ObjectIdentityImpl("my.test.Class", 1l);
		MutableAcl acl = (MutableAcl) mutableAclService.readAclById(oid);

		assertEquals(acl.getEntries().size(), 2);
		for (AccessControlEntry ace : acl.getEntries()) {
			assertEquals(ace.getAcl().getObjectIdentity(), oid);
		}

		mutableAclService.deleteAcl(oid, true);

		mutableAclService.readAclById(oid);
	}
}
