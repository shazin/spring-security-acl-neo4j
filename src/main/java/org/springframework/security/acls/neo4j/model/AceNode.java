package org.springframework.security.acls.neo4j.model;

import java.util.Objects;

import org.neo4j.graphdb.Direction;
import org.springframework.data.neo4j.annotation.GraphId;
import org.springframework.data.neo4j.annotation.NodeEntity;
import org.springframework.data.neo4j.annotation.RelatedTo;

/**
 * Ace Node to Represent Access Control Entry
 * 
 * @author shazin
 *
 */
@NodeEntity
public class AceNode extends BaseNode {

	// Graph Identifier
	@GraphId
	private Long graphId;

	// Ace Order
	private Integer aceOrder = 0;

	// Mask (Permission)
	private Integer mask = 0;

	// Granting or Non granting
	private Boolean granting = false;

	// Audit Success
	private Boolean auditSuccess = false;

	// Audit Failure
	private Boolean auditFailure = false;

	// Entry Sid 
	@RelatedTo(type = "AUTHORIZES", direction = Direction.OUTGOING)
	private SidNode entrySid;

	/**
	 * Default Contructor
	 */
	public AceNode() {
	}

	/**
	 * Conversion Constructor
	 * 
	 * @param entrySid - Entry Sid
	 * @param aceOrder - Ace Order
	 * @param mask - Mask
	 * @param granting - Granting Flag
	 * @param auditSuccess - Audit Success Flag
	 * @param auditFailure - Audit Failure Flag
	 */
	public AceNode(SidNode entrySid, Integer aceOrder, Integer mask,
			Boolean granting, Boolean auditSuccess, Boolean auditFailure) {
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
					&& Objects.equals(getAuditSuccess(),
							other.getAuditSuccess())
					&& Objects.equals(getAuditFailure(),
							other.getAuditFailure());
		}

		return false;
	}

	public int hashCode() {
		return Objects.hash(getEntrySid(), getMask(), getAceOrder(),
				getGranting(), getAuditFailure(), getAuditSuccess());
	}

	public String toString() {
		return "AceNode[id=" + getId() + ",sid=" + getEntrySid() + ",mask="
				+ getMask() + "]";
	}

}
