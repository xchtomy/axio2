package jp.co.axio.masterMentsetSystem.model;

public class MRuleDetailEntityKey {
    private String ruleId;

    private String ruleDetailId;

    private String ruleDetailFlag;

    public String getRuleId() {
        return ruleId;
    }

    public void setRuleId(String ruleId) {
        this.ruleId = ruleId == null ? null : ruleId.trim();
    }

    public String getRuleDetailId() {
        return ruleDetailId;
    }

    public void setRuleDetailId(String ruleDetailId) {
        this.ruleDetailId = ruleDetailId == null ? null : ruleDetailId.trim();
    }

    public String getRuleDetailFlag() {
        return ruleDetailFlag;
    }

    public void setRuleDetailFlag(String ruleDetailFlag) {
        this.ruleDetailFlag = ruleDetailFlag == null ? null : ruleDetailFlag.trim();
    }
}