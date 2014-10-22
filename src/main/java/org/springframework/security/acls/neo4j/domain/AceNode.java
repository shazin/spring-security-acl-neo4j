package org.springframework.security.acls.neo4j.domain;

import java.util.Objects;

import org.neo4j.graphdb.Direction;
import org.springframework.data.neo4j.annotation.GraphId;
import org.springframework.data.neo4j.annotation.NodeEntity;
import org.springframework.data.neo4j.annotation.RelatedTo;

@NodeEntity
public class AceNode extends BaseNode {

	@GraphId
	private Long graphId;

	private Integer aceOrder = 0;

	private Integer mask = 0;

	private Boolean granting = false;

	private Boolean auditSuccess = false;

	private Boolean auditFailure = false;
	
	@RelatedTo(type = "AUTHORIZES", direction=Direction.OUTGOING)
	private SidNode entrySid;
	
	public AceNode() {}
	
	public AceNode(SidNode entrySid, Integer aceOrder, Integer mask, Boolean granting,
			Boolean auditSuccess, Boolean auditFailure) {
		this();
		this.entrySid = entrySid;
		this.aceOrder = aceOrder;
		this.mask = mask;
		this.granting = granting;
		this.auditSuccess = auditSuccess;
		this.auditFailure = auditFailure;
	}

	public Long getGraphId() {
		return graphId;
	}

	public void setGraphId(Long graphId) {
		this.graphId = graphId;
	}

	public Integer getAceOrder() {
		return aceOrder;
	}

	public void setAceOrder(Integer aceOrder) {
		this.aceOrder = aceOrder;
	}

	public Integer getMask() {
		return mask;
	}

	public void setMask(Integer mask) {
		this.mask = mask;
	}

	public Boolean getGranting() {
		return granting;
	}

	public void setGranting(Boolean granting) {
		this.granting = granting;
	}

	public Boolean getAuditSuccess() {
		return auditSuccess;
	}

	public void setAuditSuccess(Boolean auditSuccess) {
		this.auditSuccess = auditSuccess;
	}

	public Boolean getAuditFailure() {
		return auditFailure;
	}

	public void setAuditFailure(Boolean auditFailure) {
		this.auditFailure = auditFailure;
	}	

	public SidNode getEntrySid() {
		return entrySid;
	}

	public void setEntrySid(SidNode entrySid) {
		this.entrySid = entrySid;
	}

	public boolean equals(Object o) {
		if (o == null) {
			return false;
		}

		if (o == this) {
			return true;
		}

		if (o instanceof AceNode) {
			AceNode other = (AceNode) o;
			return Objects.equals(getEntrySid(), other.getEntrySid()) 
					&& Objects.equals(getMask(), other.getMask())
					&& Objects.equals(getAceOrder(), other.getAceOrder())
					&& Objects.equals(getGranting(), other.getGranting())
					&& Objects.equals(getAuditSuccess(), other.getAuditSuccess()) 
					&& Objects.equals(getAuditFailure(), other.getAuditFailure());
		}
		
		return false;
	}
	
	public int hashCode() {
		return Objects.hash(getEntrySid(), getMask(), getAceOrder(), getGranting(), getAuditFailure(), getAuditSuccess());
	}
	
	public String toString() {
		return "AceNode[id=" + getId() +",sid="+getEntrySid()+",mask="+getMask()+"]";
	}

}
