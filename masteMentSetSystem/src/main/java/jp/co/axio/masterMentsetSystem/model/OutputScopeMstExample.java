package jp.co.axio.masterMentsetSystem.model;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class OutputScopeMstExample {
    protected String orderByClause;

    protected boolean distinct;

    protected List<Criteria> oredCriteria;

    public OutputScopeMstExample() {
        oredCriteria = new ArrayList<>();
    }

    public void setOrderByClause(String orderByClause) {
        this.orderByClause = orderByClause;
    }

    public String getOrderByClause() {
        return orderByClause;
    }

    public void setDistinct(boolean distinct) {
        this.distinct = distinct;
    }

    public boolean isDistinct() {
        return distinct;
    }

    public List<Criteria> getOredCriteria() {
        return oredCriteria;
    }

    public void or(Criteria criteria) {
        oredCriteria.add(criteria);
    }

    public Criteria or() {
        Criteria criteria = createCriteriaInternal();
        oredCriteria.add(criteria);
        return criteria;
    }

    public Criteria createCriteria() {
        Criteria criteria = createCriteriaInternal();
        if (oredCriteria.size() == 0) {
            oredCriteria.add(criteria);
        }
        return criteria;
    }

    protected Criteria createCriteriaInternal() {
        Criteria criteria = new Criteria();
        return criteria;
    }

    public void clear() {
        oredCriteria.clear();
        orderByClause = null;
        distinct = false;
    }

    protected abstract static class GeneratedCriteria {
        protected List<Criterion> criteria;

        protected GeneratedCriteria() {
            super();
            criteria = new ArrayList<>();
        }

        public boolean isValid() {
            return criteria.size() > 0;
        }

        public List<Criterion> getAllCriteria() {
            return criteria;
        }

        public List<Criterion> getCriteria() {
            return criteria;
        }

        protected void addCriterion(String condition) {
            if (condition == null) {
                throw new RuntimeException("Value for condition cannot be null");
            }
            criteria.add(new Criterion(condition));
        }

        protected void addCriterion(String condition, Object value, String property) {
            if (value == null) {
                throw new RuntimeException("Value for " + property + " cannot be null");
            }
            criteria.add(new Criterion(condition, value));
        }

        protected void addCriterion(String condition, Object value1, Object value2, String property) {
            if (value1 == null || value2 == null) {
                throw new RuntimeException("Between values for " + property + " cannot be null");
            }
            criteria.add(new Criterion(condition, value1, value2));
        }

        public Criteria andOutputScopeNoIsNull() {
            addCriterion("output_scope_no is null");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNoIsNotNull() {
            addCriterion("output_scope_no is not null");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNoEqualTo(Integer value) {
            addCriterion("output_scope_no =", value, "outputScopeNo");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNoNotEqualTo(Integer value) {
            addCriterion("output_scope_no <>", value, "outputScopeNo");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNoGreaterThan(Integer value) {
            addCriterion("output_scope_no >", value, "outputScopeNo");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNoGreaterThanOrEqualTo(Integer value) {
            addCriterion("output_scope_no >=", value, "outputScopeNo");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNoLessThan(Integer value) {
            addCriterion("output_scope_no <", value, "outputScopeNo");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNoLessThanOrEqualTo(Integer value) {
            addCriterion("output_scope_no <=", value, "outputScopeNo");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNoIn(List<Integer> values) {
            addCriterion("output_scope_no in", values, "outputScopeNo");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNoNotIn(List<Integer> values) {
            addCriterion("output_scope_no not in", values, "outputScopeNo");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNoBetween(Integer value1, Integer value2) {
            addCriterion("output_scope_no between", value1, value2, "outputScopeNo");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNoNotBetween(Integer value1, Integer value2) {
            addCriterion("output_scope_no not between", value1, value2, "outputScopeNo");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNameIsNull() {
            addCriterion("output_scope_name is null");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNameIsNotNull() {
            addCriterion("output_scope_name is not null");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNameEqualTo(String value) {
            addCriterion("output_scope_name =", value, "outputScopeName");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNameNotEqualTo(String value) {
            addCriterion("output_scope_name <>", value, "outputScopeName");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNameGreaterThan(String value) {
            addCriterion("output_scope_name >", value, "outputScopeName");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNameGreaterThanOrEqualTo(String value) {
            addCriterion("output_scope_name >=", value, "outputScopeName");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNameLessThan(String value) {
            addCriterion("output_scope_name <", value, "outputScopeName");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNameLessThanOrEqualTo(String value) {
            addCriterion("output_scope_name <=", value, "outputScopeName");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNameLike(String value) {
            addCriterion("output_scope_name like", value, "outputScopeName");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNameNotLike(String value) {
            addCriterion("output_scope_name not like", value, "outputScopeName");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNameIn(List<String> values) {
            addCriterion("output_scope_name in", values, "outputScopeName");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNameNotIn(List<String> values) {
            addCriterion("output_scope_name not in", values, "outputScopeName");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNameBetween(String value1, String value2) {
            addCriterion("output_scope_name between", value1, value2, "outputScopeName");
            return (Criteria) this;
        }

        public Criteria andOutputScopeNameNotBetween(String value1, String value2) {
            addCriterion("output_scope_name not between", value1, value2, "outputScopeName");
            return (Criteria) this;
        }

        public Criteria andOutputScopeTableIsNull() {
            addCriterion("output_scope_table is null");
            return (Criteria) this;
        }

        public Criteria andOutputScopeTableIsNotNull() {
            addCriterion("output_scope_table is not null");
            return (Criteria) this;
        }

        public Criteria andOutputScopeTableEqualTo(String value) {
            addCriterion("output_scope_table =", value, "outputScopeTable");
            return (Criteria) this;
        }

        public Criteria andOutputScopeTableNotEqualTo(String value) {
            addCriterion("output_scope_table <>", value, "outputScopeTable");
            return (Criteria) this;
        }

        public Criteria andOutputScopeTableGreaterThan(String value) {
            addCriterion("output_scope_table >", value, "outputScopeTable");
            return (Criteria) this;
        }

        public Criteria andOutputScopeTableGreaterThanOrEqualTo(String value) {
            addCriterion("output_scope_table >=", value, "outputScopeTable");
            return (Criteria) this;
        }

        public Criteria andOutputScopeTableLessThan(String value) {
            addCriterion("output_scope_table <", value, "outputScopeTable");
            return (Criteria) this;
        }

        public Criteria andOutputScopeTableLessThanOrEqualTo(String value) {
            addCriterion("output_scope_table <=", value, "outputScopeTable");
            return (Criteria) this;
        }

        public Criteria andOutputScopeTableLike(String value) {
            addCriterion("output_scope_table like", value, "outputScopeTable");
            return (Criteria) this;
        }

        public Criteria andOutputScopeTableNotLike(String value) {
            addCriterion("output_scope_table not like", value, "outputScopeTable");
            return (Criteria) this;
        }

        public Criteria andOutputScopeTableIn(List<String> values) {
            addCriterion("output_scope_table in", values, "outputScopeTable");
            return (Criteria) this;
        }

        public Criteria andOutputScopeTableNotIn(List<String> values) {
            addCriterion("output_scope_table not in", values, "outputScopeTable");
            return (Criteria) this;
        }

        public Criteria andOutputScopeTableBetween(String value1, String value2) {
            addCriterion("output_scope_table between", value1, value2, "outputScopeTable");
            return (Criteria) this;
        }

        public Criteria andOutputScopeTableNotBetween(String value1, String value2) {
            addCriterion("output_scope_table not between", value1, value2, "outputScopeTable");
            return (Criteria) this;
        }

        public Criteria andRegisterIdIsNull() {
            addCriterion("register_id is null");
            return (Criteria) this;
        }

        public Criteria andRegisterIdIsNotNull() {
            addCriterion("register_id is not null");
            return (Criteria) this;
        }

        public Criteria andRegisterIdEqualTo(String value) {
            addCriterion("register_id =", value, "registerId");
            return (Criteria) this;
        }

        public Criteria andRegisterIdNotEqualTo(String value) {
            addCriterion("register_id <>", value, "registerId");
            return (Criteria) this;
        }

        public Criteria andRegisterIdGreaterThan(String value) {
            addCriterion("register_id >", value, "registerId");
            return (Criteria) this;
        }

        public Criteria andRegisterIdGreaterThanOrEqualTo(String value) {
            addCriterion("register_id >=", value, "registerId");
            return (Criteria) this;
        }

        public Criteria andRegisterIdLessThan(String value) {
            addCriterion("register_id <", value, "registerId");
            return (Criteria) this;
        }

        public Criteria andRegisterIdLessThanOrEqualTo(String value) {
            addCriterion("register_id <=", value, "registerId");
            return (Criteria) this;
        }

        public Criteria andRegisterIdLike(String value) {
            addCriterion("register_id like", value, "registerId");
            return (Criteria) this;
        }

        public Criteria andRegisterIdNotLike(String value) {
            addCriterion("register_id not like", value, "registerId");
            return (Criteria) this;
        }

        public Criteria andRegisterIdIn(List<String> values) {
            addCriterion("register_id in", values, "registerId");
            return (Criteria) this;
        }

        public Criteria andRegisterIdNotIn(List<String> values) {
            addCriterion("register_id not in", values, "registerId");
            return (Criteria) this;
        }

        public Criteria andRegisterIdBetween(String value1, String value2) {
            addCriterion("register_id between", value1, value2, "registerId");
            return (Criteria) this;
        }

        public Criteria andRegisterIdNotBetween(String value1, String value2) {
            addCriterion("register_id not between", value1, value2, "registerId");
            return (Criteria) this;
        }

        public Criteria andRegistTsIsNull() {
            addCriterion("regist_ts is null");
            return (Criteria) this;
        }

        public Criteria andRegistTsIsNotNull() {
            addCriterion("regist_ts is not null");
            return (Criteria) this;
        }

        public Criteria andRegistTsEqualTo(Date value) {
            addCriterion("regist_ts =", value, "registTs");
            return (Criteria) this;
        }

        public Criteria andRegistTsNotEqualTo(Date value) {
            addCriterion("regist_ts <>", value, "registTs");
            return (Criteria) this;
        }

        public Criteria andRegistTsGreaterThan(Date value) {
            addCriterion("regist_ts >", value, "registTs");
            return (Criteria) this;
        }

        public Criteria andRegistTsGreaterThanOrEqualTo(Date value) {
            addCriterion("regist_ts >=", value, "registTs");
            return (Criteria) this;
        }

        public Criteria andRegistTsLessThan(Date value) {
            addCriterion("regist_ts <", value, "registTs");
            return (Criteria) this;
        }

        public Criteria andRegistTsLessThanOrEqualTo(Date value) {
            addCriterion("regist_ts <=", value, "registTs");
            return (Criteria) this;
        }

        public Criteria andRegistTsIn(List<Date> values) {
            addCriterion("regist_ts in", values, "registTs");
            return (Criteria) this;
        }

        public Criteria andRegistTsNotIn(List<Date> values) {
            addCriterion("regist_ts not in", values, "registTs");
            return (Criteria) this;
        }

        public Criteria andRegistTsBetween(Date value1, Date value2) {
            addCriterion("regist_ts between", value1, value2, "registTs");
            return (Criteria) this;
        }

        public Criteria andRegistTsNotBetween(Date value1, Date value2) {
            addCriterion("regist_ts not between", value1, value2, "registTs");
            return (Criteria) this;
        }

        public Criteria andUpdaterIdIsNull() {
            addCriterion("updater_id is null");
            return (Criteria) this;
        }

        public Criteria andUpdaterIdIsNotNull() {
            addCriterion("updater_id is not null");
            return (Criteria) this;
        }

        public Criteria andUpdaterIdEqualTo(String value) {
            addCriterion("updater_id =", value, "updaterId");
            return (Criteria) this;
        }

        public Criteria andUpdaterIdNotEqualTo(String value) {
            addCriterion("updater_id <>", value, "updaterId");
            return (Criteria) this;
        }

        public Criteria andUpdaterIdGreaterThan(String value) {
            addCriterion("updater_id >", value, "updaterId");
            return (Criteria) this;
        }

        public Criteria andUpdaterIdGreaterThanOrEqualTo(String value) {
            addCriterion("updater_id >=", value, "updaterId");
            return (Criteria) this;
        }

        public Criteria andUpdaterIdLessThan(String value) {
            addCriterion("updater_id <", value, "updaterId");
            return (Criteria) this;
        }

        public Criteria andUpdaterIdLessThanOrEqualTo(String value) {
            addCriterion("updater_id <=", value, "updaterId");
            return (Criteria) this;
        }

        public Criteria andUpdaterIdLike(String value) {
            addCriterion("updater_id like", value, "updaterId");
            return (Criteria) this;
        }

        public Criteria andUpdaterIdNotLike(String value) {
            addCriterion("updater_id not like", value, "updaterId");
            return (Criteria) this;
        }

        public Criteria andUpdaterIdIn(List<String> values) {
            addCriterion("updater_id in", values, "updaterId");
            return (Criteria) this;
        }

        public Criteria andUpdaterIdNotIn(List<String> values) {
            addCriterion("updater_id not in", values, "updaterId");
            return (Criteria) this;
        }

        public Criteria andUpdaterIdBetween(String value1, String value2) {
            addCriterion("updater_id between", value1, value2, "updaterId");
            return (Criteria) this;
        }

        public Criteria andUpdaterIdNotBetween(String value1, String value2) {
            addCriterion("updater_id not between", value1, value2, "updaterId");
            return (Criteria) this;
        }

        public Criteria andUpdateTsIsNull() {
            addCriterion("update_ts is null");
            return (Criteria) this;
        }

        public Criteria andUpdateTsIsNotNull() {
            addCriterion("update_ts is not null");
            return (Criteria) this;
        }

        public Criteria andUpdateTsEqualTo(Date value) {
            addCriterion("update_ts =", value, "updateTs");
            return (Criteria) this;
        }

        public Criteria andUpdateTsNotEqualTo(Date value) {
            addCriterion("update_ts <>", value, "updateTs");
            return (Criteria) this;
        }

        public Criteria andUpdateTsGreaterThan(Date value) {
            addCriterion("update_ts >", value, "updateTs");
            return (Criteria) this;
        }

        public Criteria andUpdateTsGreaterThanOrEqualTo(Date value) {
            addCriterion("update_ts >=", value, "updateTs");
            return (Criteria) this;
        }

        public Criteria andUpdateTsLessThan(Date value) {
            addCriterion("update_ts <", value, "updateTs");
            return (Criteria) this;
        }

        public Criteria andUpdateTsLessThanOrEqualTo(Date value) {
            addCriterion("update_ts <=", value, "updateTs");
            return (Criteria) this;
        }

        public Criteria andUpdateTsIn(List<Date> values) {
            addCriterion("update_ts in", values, "updateTs");
            return (Criteria) this;
        }

        public Criteria andUpdateTsNotIn(List<Date> values) {
            addCriterion("update_ts not in", values, "updateTs");
            return (Criteria) this;
        }

        public Criteria andUpdateTsBetween(Date value1, Date value2) {
            addCriterion("update_ts between", value1, value2, "updateTs");
            return (Criteria) this;
        }

        public Criteria andUpdateTsNotBetween(Date value1, Date value2) {
            addCriterion("update_ts not between", value1, value2, "updateTs");
            return (Criteria) this;
        }

        public Criteria andVersionNumberIsNull() {
            addCriterion("version_number is null");
            return (Criteria) this;
        }

        public Criteria andVersionNumberIsNotNull() {
            addCriterion("version_number is not null");
            return (Criteria) this;
        }

        public Criteria andVersionNumberEqualTo(Integer value) {
            addCriterion("version_number =", value, "versionNumber");
            return (Criteria) this;
        }

        public Criteria andVersionNumberNotEqualTo(Integer value) {
            addCriterion("version_number <>", value, "versionNumber");
            return (Criteria) this;
        }

        public Criteria andVersionNumberGreaterThan(Integer value) {
            addCriterion("version_number >", value, "versionNumber");
            return (Criteria) this;
        }

        public Criteria andVersionNumberGreaterThanOrEqualTo(Integer value) {
            addCriterion("version_number >=", value, "versionNumber");
            return (Criteria) this;
        }

        public Criteria andVersionNumberLessThan(Integer value) {
            addCriterion("version_number <", value, "versionNumber");
            return (Criteria) this;
        }

        public Criteria andVersionNumberLessThanOrEqualTo(Integer value) {
            addCriterion("version_number <=", value, "versionNumber");
            return (Criteria) this;
        }

        public Criteria andVersionNumberIn(List<Integer> values) {
            addCriterion("version_number in", values, "versionNumber");
            return (Criteria) this;
        }

        public Criteria andVersionNumberNotIn(List<Integer> values) {
            addCriterion("version_number not in", values, "versionNumber");
            return (Criteria) this;
        }

        public Criteria andVersionNumberBetween(Integer value1, Integer value2) {
            addCriterion("version_number between", value1, value2, "versionNumber");
            return (Criteria) this;
        }

        public Criteria andVersionNumberNotBetween(Integer value1, Integer value2) {
            addCriterion("version_number not between", value1, value2, "versionNumber");
            return (Criteria) this;
        }
    }

    public static class Criteria extends GeneratedCriteria {
        protected Criteria() {
            super();
        }
    }

    public static class Criterion {
        private String condition;

        private Object value;

        private Object secondValue;

        private boolean noValue;

        private boolean singleValue;

        private boolean betweenValue;

        private boolean listValue;

        private String typeHandler;

        public String getCondition() {
            return condition;
        }

        public Object getValue() {
            return value;
        }

        public Object getSecondValue() {
            return secondValue;
        }

        public boolean isNoValue() {
            return noValue;
        }

        public boolean isSingleValue() {
            return singleValue;
        }

        public boolean isBetweenValue() {
            return betweenValue;
        }

        public boolean isListValue() {
            return listValue;
        }

        public String getTypeHandler() {
            return typeHandler;
        }

        protected Criterion(String condition) {
            super();
            this.condition = condition;
            this.typeHandler = null;
            this.noValue = true;
        }

        protected Criterion(String condition, Object value, String typeHandler) {
            super();
            this.condition = condition;
            this.value = value;
            this.typeHandler = typeHandler;
            if (value instanceof List<?>) {
                this.listValue = true;
            } else {
                this.singleValue = true;
            }
        }

        protected Criterion(String condition, Object value) {
            this(condition, value, null);
        }

        protected Criterion(String condition, Object value, Object secondValue, String typeHandler) {
            super();
            this.condition = condition;
            this.value = value;
            this.secondValue = secondValue;
            this.typeHandler = typeHandler;
            this.betweenValue = true;
        }

        protected Criterion(String condition, Object value, Object secondValue) {
            this(condition, value, secondValue, null);
        }
    }
}