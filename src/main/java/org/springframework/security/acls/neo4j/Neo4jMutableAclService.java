package org.springframework.security.acls.neo4j;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.neo4j.graphdb.GraphDatabaseService;
import org.springframework.dao.DataAccessException;
import org.springframework.data.neo4j.conversion.Result;
import org.springframework.security.acls.domain.AccessControlEntryImpl;
import org.springframework.security.acls.domain.GrantedAuthoritySid;
import org.springframework.security.acls.domain.ObjectIdentityImpl;
import org.springframework.security.acls.domain.PrincipalSid;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.acls.model.AclCache;
import org.springframework.security.acls.model.AlreadyExistsException;
import org.springframework.security.acls.model.ChildrenExistException;
import org.springframework.security.acls.model.MutableAcl;
import org.springframework.security.acls.model.MutableAclService;
import org.springframework.security.acls.model.NotFoundException;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.security.acls.model.Sid;
import org.springframework.security.acls.neo4j.domain.AceNode;
import org.springframework.security.acls.neo4j.domain.AclNode;
import org.springframework.security.acls.neo4j.domain.ClassNode;
import org.springframework.security.acls.neo4j.domain.SidNode;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.Assert;

@Transactional(readOnly=true)
public class Neo4jMutableAclService extends Neo4jAclService implements MutableAclService {

	//private String insertObjectIdentity = "MATCH (class:ClassNode), (sid:SidNode) WHERE class.className = {className} AND sid.sid = {sid} AND sid.principal = {principal} CREATE (acl:AclNode {objectIdIdentity: {objectIdIdentity}, entriesInheriting: {entriesInheriting}), (acl)-[:SECURES]->(class), (acl)-[:OWNED_BY]"
	private String selectObjectIdentity = "MATCH (class:ClassNode)<-[:SECURES]-(acl:AclNode) WHERE acl.objectIdIdentity = {objectIdIdentity} and class.className = {className} RETURN acl";
	private String selectSid = "MATCH (sid:SidNode) WHERE sid.sid = {sid} AND sid.principal = {principal} RETURN sid";
	private String selectClass = "MATCH (class:ClassNode) WHERE class.className = {className} RETURN class";
	private String deleteEntryByObjectIdentityForeignKey = "MATCH (acl:AclNode) OPTIONAL MATCH (acl)<-[c:COMPOSES]-(ace:AceNode)-[a:AUTHORIZES]->(sid:SidNode) WHERE acl.id = {aclId} DELETE c, a, ace";
	private String deleteObjectIdentityByPrimaryKey = "MATCH (owner:SidNode)<-[o:OWNED_BY]-(acl:AclNode)-[s:SECURES]->(class:ClassNode) WHERE acl.id = {aclId} DELETE s, o, acl";
	
	
	public Neo4jMutableAclService(GraphDatabaseService graphDatabaseService, AclCache aclCache, LookupStrategy lookupStrategy) {
		super(graphDatabaseService, lookupStrategy, aclCache);
	}
	
	@Override
	@Transactional(rollbackFor=Exception.class)
	public MutableAcl createAcl(ObjectIdentity objectIdentity)
			throws AlreadyExistsException {
		Assert.notNull(objectIdentity, "Object Identity required");

        // Check this object identity hasn't already been persisted
        if (retrieveObjectIdentityPrimaryKey(objectIdentity) != null) {
            throw new AlreadyExistsException("Object identity '" + objectIdentity + "' already exists");
        }

        // Need to retrieve the current principal, in order to know who "owns" this ACL (can be changed later on)
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        PrincipalSid sid = new PrincipalSid(auth);

        // Create the acl_object_identity row
        createObjectIdentity(objectIdentity, sid);

        // Retrieve the ACL via superclass (ensures cache registration, proper retrieval etc)
        Acl acl = readAclById(objectIdentity);
        Assert.isInstanceOf(MutableAcl.class, acl, "MutableAcl should be been returned");

        return (MutableAcl) acl;
	}

	@Override
	@Transactional(rollbackFor=Exception.class)
	public void deleteAcl(ObjectIdentity objectIdentity, boolean deleteChildren)
			throws ChildrenExistException {
		Assert.notNull(objectIdentity, "Object Identity required");
        Assert.notNull(objectIdentity.getIdentifier(), "Object Identity doesn't provide an identifier");

        if (deleteChildren) {
            List<ObjectIdentity> children = findChildren(objectIdentity);
            if (children != null) {
                for (ObjectIdentity child : children) {
                    deleteAcl(child, true);
                }
            }
        } 

        String oidPrimaryKey = retrieveObjectIdentityPrimaryKey(objectIdentity);

        // Delete this ACL's ACEs in the acl_entry table
        deleteEntries(oidPrimaryKey);

        // Delete this ACL's acl_object_identity row
        deleteObjectIdentity(oidPrimaryKey);

        // Clear the cache
        aclCache.evictFromCache(objectIdentity);
	}

	@Override
	@Transactional(rollbackFor=Exception.class)
	public MutableAcl updateAcl(MutableAcl acl) throws NotFoundException {
		Assert.notNull(acl.getId(), "Object Identity doesn't provide an identifier");

        // Delete this ACL's ACEs in the acl_entry table
        deleteEntries(retrieveObjectIdentityPrimaryKey(acl.getObjectIdentity()));

        // Create this ACL's ACEs in the acl_entry table
        createEntries(acl);

        // Change the mutable columns in acl_object_identity
        updateObjectIdentity(acl);

        // Clear the cache, including children
        clearCacheIncludingChildren(acl.getObjectIdentity());

        // Retrieve the ACL via superclass (ensures cache registration, proper retrieval etc)
        return (MutableAcl) super.readAclById(acl.getObjectIdentity());
	}
	
	protected String retrieveObjectIdentityPrimaryKey(ObjectIdentity oid) {
        try {
        	AclNode acl = retrieveAclNode(oid);
            if(acl == null) {
            	return null;
            } else {
            	return acl.getId();
            }
        } catch (DataAccessException notFound) {
            return null;
        }
    }

	private AclNode retrieveAclNode(ObjectIdentity oid) {
		Map<String, Object> params = new HashMap<String, Object>();
		params.put("objectIdIdentity", (Long) oid.getIdentifier());
		params.put("className", oid.getType());
		Result<Map<String, Object>> result = neo4jTemplate.query(selectObjectIdentity, params);
		Result<AclNode> aclNode = result.to(AclNode.class);
		AclNode acl =  aclNode.singleOrNull();
		return acl;
	}
	
	protected void createObjectIdentity(ObjectIdentity object, Sid owner) {
		Assert.isTrue(TransactionSynchronizationManager.isSynchronizationActive(), "Transaction must be running");
        SidNode sid = createOrRetrieveSid(owner, true);
        ClassNode classNode = createOrRetrieveClass(object.getType(), true);
        AclNode aclNode = new AclNode(Boolean.TRUE, (Long) object.getIdentifier(), null, classNode, sid);
        AclNode savedAcl = neo4jTemplate.save(aclNode);
    }
	
	protected SidNode createOrRetrieveSid(Sid sid, boolean allowCreate) {
        Assert.notNull(sid, "Sid required");

        String sidName;
        boolean sidIsPrincipal = true;

        if (sid instanceof PrincipalSid) {
            sidName = ((PrincipalSid) sid).getPrincipal();
        } else if (sid instanceof GrantedAuthoritySid) {
            sidName = ((GrantedAuthoritySid) sid).getGrantedAuthority();
            sidIsPrincipal = false;
        } else {
            throw new IllegalArgumentException("Unsupported implementation of Sid");
        }

        Map<String, Object> params = new HashMap<String, Object>();
        params.put("sid", sidName);
        params.put("principal", sidIsPrincipal);
        Result<Map<String, Object>> result = neo4jTemplate.query(selectSid, params);
        Result<SidNode> sidNode = result.to(SidNode.class);
        
        if(sidNode.iterator().hasNext()) {
        	return sidNode.iterator().next();
        }
        
        if (allowCreate) {
        	SidNode newSid = new SidNode(sidName, sidIsPrincipal);
        	SidNode savedSid = neo4jTemplate.save(newSid);
            return savedSid;
        }

        return null;
    }
	
	protected ClassNode createOrRetrieveClass(String type, boolean allowCreate) {
		Map<String, Object> params = new HashMap<String, Object>();
        params.put("className", type);
        Result<Map<String, Object>> result = neo4jTemplate.query(selectClass, params);
        Result<ClassNode> classNode = result.to(ClassNode.class);
        
        if(classNode.iterator().hasNext()) {
        	return classNode.iterator().next();
        }

        if (allowCreate) {
            ClassNode newClassNode = new ClassNode(type);
            ClassNode savedClassNode = neo4jTemplate.save(newClassNode);
            return savedClassNode;
        }

        return null;
    }
	
    protected void deleteEntries(String oidPrimaryKey) {
    	Map<String, Object> params = new HashMap<String, Object>();
        params.put("aclId", oidPrimaryKey);
        neo4jTemplate.query(deleteEntryByObjectIdentityForeignKey, params);
    }

    protected void deleteObjectIdentity(String oidPrimaryKey) {
    	Map<String, Object> params = new HashMap<String, Object>();
        params.put("aclId", oidPrimaryKey);
        neo4jTemplate.query(deleteObjectIdentityByPrimaryKey, params);
    }
    
    protected void createEntries(final MutableAcl acl) {
        if(acl.getEntries().isEmpty()) {
            return;
        }
        AclNode aclNode = retrieveAclNode(acl.getObjectIdentity());
    	if(aclNode == null) {
    		return;
    	}
    	Set<AceNode> aces = new HashSet<AceNode>();
    	int i = aclNode.getAces().size();
    	for(AccessControlEntry ace:acl.getEntries()) {
    		AccessControlEntryImpl entry = (AccessControlEntryImpl) ace;
    		aces.add(neo4jTemplate.save(new AceNode(createOrRetrieveSid(entry.getSid(), true), i, entry.getPermission().getMask(), entry.isGranting(), entry.isAuditSuccess(), entry.isAuditFailure())));
    				i++;
    	}
    	aclNode.setAces(aces);
    	AclNode savedAclNode = neo4jTemplate.save(aclNode);
    }
    
    protected void updateObjectIdentity(MutableAcl acl) {
        String parentId = null;

        if (acl.getParentAcl() != null) {
            Assert.isInstanceOf(ObjectIdentityImpl.class, acl.getParentAcl().getObjectIdentity(),
                "Implementation only supports ObjectIdentityImpl");

            ObjectIdentityImpl oii = (ObjectIdentityImpl) acl.getParentAcl().getObjectIdentity();
            parentId = retrieveObjectIdentityPrimaryKey(oii);
        }

        Assert.notNull(acl.getOwner(), "Owner is required in this implementation");

        SidNode ownerSid = createOrRetrieveSid(acl.getOwner(), true);
        AclNode aclNode = retrieveAclNode(acl.getObjectIdentity());
    	
    	if (aclNode == null) {
            throw new NotFoundException("Unable to locate ACL to update");
        }
    	
    	aclNode.setOwnerSid(ownerSid);
    	aclNode.setParentObject(parentId);
    	aclNode.setEntriesInheriting(acl.isEntriesInheriting());
    	
        neo4jTemplate.save(aclNode);        
    }
    
    private void clearCacheIncludingChildren(ObjectIdentity objectIdentity) {
        Assert.notNull(objectIdentity, "ObjectIdentity required");
        List<ObjectIdentity> children = findChildren(objectIdentity);
        if (children != null) {
            for (ObjectIdentity child : children) {
                clearCacheIncludingChildren(child);
            }
        }
        aclCache.evictFromCache(objectIdentity);
    }

	public String getSelectObjectIdentity() {
		return selectObjectIdentity;
	}

	public void setSelectObjectIdentity(String selectObjectIdentity) {
		this.selectObjectIdentity = selectObjectIdentity;
	}

	public String getSelectSid() {
		return selectSid;
	}

	public void setSelectSid(String selectSid) {
		this.selectSid = selectSid;
	}

	public String getSelectClass() {
		return selectClass;
	}

	public void setSelectClass(String selectClass) {
		this.selectClass = selectClass;
	}

	public String getDeleteEntryByObjectIdentityForeignKey() {
		return deleteEntryByObjectIdentityForeignKey;
	}

	public void setDeleteEntryByObjectIdentityForeignKey(
			String deleteEntryByObjectIdentityForeignKey) {
		this.deleteEntryByObjectIdentityForeignKey = deleteEntryByObjectIdentityForeignKey;
	}

	public String getDeleteObjectIdentityByPrimaryKey() {
		return deleteObjectIdentityByPrimaryKey;
	}

	public void setDeleteObjectIdentityByPrimaryKey(
			String deleteObjectIdentityByPrimaryKey) {
		this.deleteObjectIdentityByPrimaryKey = deleteObjectIdentityByPrimaryKey;
	}
    
    


}
