package jp.co.axio.masterMentsetSystem.model;

import java.util.Date;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ShMAdgroupEntity {

	private String companyCode;
	private String organizationCode;
	private String groupIdFile;
	private String groupNameFile;
	private String fileMngFlag;
	private String groupIdFileMng;
	private String groupIdMail;
	private String groupNameMail;
	private String excludeTempFlag;
	private String note;
	private String invalidFlag;
	private String registerId;
	private Date registTs;
	private String updaterId;
	private Date updateTs;
	private Date reflecionDate;
	private String value7;
}
