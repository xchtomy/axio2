package jp.co.axio.masterMentsetSystem.model;

import java.util.Date;

public class MRuleGroupEnRec extends MRuleGroupEntity {
    private String groupId;

    private String groupNameEn;

    private String groupNameJp;

    private Date startDate;

    private Date endDate;

    private String note;

    private String invalidFlag;

    public String getGroupId() {
        return groupId;
    }

    public void setGroupId(String groupId) {
        this.groupId = groupId == null ? null : groupId.trim();
    }

    public String getGroupNameEn() {
        return groupNameEn;
    }

    public void setGroupNameEn(String groupNameEn) {
        this.groupNameEn = groupNameEn == null ? null : groupNameEn.trim();
    }

    public String getGroupNameJp() {
        return groupNameJp;
    }

    public void setGroupNameJp(String groupNameJp) {
        this.groupNameJp = groupNameJp == null ? null : groupNameJp.trim();
    }

    public Date getStartDate() {
        return startDate;
    }

    public void setStartDate(Date startDate) {
        this.startDate = startDate;
    }

    public Date getEndDate() {
        return endDate;
    }

    public void setEndDate(Date endDate) {
        this.endDate = endDate;
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note == null ? null : note.trim();
    }

    public String getInvalidFlag() {
        return invalidFlag;
    }

    public void setInvalidFlag(String invalidFlag) {
        this.invalidFlag = invalidFlag == null ? null : invalidFlag.trim();
    }

}