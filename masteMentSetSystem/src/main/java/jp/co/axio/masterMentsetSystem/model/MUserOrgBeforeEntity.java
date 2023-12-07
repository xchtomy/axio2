package jp.co.axio.masterMentsetSystem.model;

import java.util.Date;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class MUserOrgBeforeEntity {

	private String userId;
	private String companyCode;
	private String organizationCode;
	private Date startDate;
	private Date endDate;
	private String invalidFlag;
	private String organizationKbn;
	private String locationCode;
	private String registerId;
	private Date registTs;
	private String updaterId;
	private Date updateTs;
	private String positionCode;
	private String concurrencyOrder;

}