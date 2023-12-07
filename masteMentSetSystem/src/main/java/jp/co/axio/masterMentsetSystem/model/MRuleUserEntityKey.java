package jp.co.axio.masterMentsetSystem.model;

public class MRuleUserEntityKey {
    private String ruleId;

    private String userId;

    private String exclusionFlag;

    public String getRuleId() {
        return ruleId;
    }

    public void setRuleId(String ruleId) {
        this.ruleId = ruleId == null ? null : ruleId.trim();
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId == null ? null : userId.trim();
    }

    public String getExclusionFlag() {
        return exclusionFlag;
    }

    public void setExclusionFlag(String exclusionFlag) {
        this.exclusionFlag = exclusionFlag == null ? null : exclusionFlag.trim();
    }
}