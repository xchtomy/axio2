package jp.co.axio.masterMentsetSystem.model;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class MgpCodeMstExample {
    protected String orderByClause;

    protected boolean distinct;

    protected List<Criteria> oredCriteria;

    public MgpCodeMstExample() {
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

        public Criteria andClassCodeIsNull() {
            addCriterion("class_code is null");
            return (Criteria) this;
        }

        public Criteria andClassCodeIsNotNull() {
            addCriterion("class_code is not null");
            return (Criteria) this;
        }

        public Criteria andClassCodeEqualTo(String value) {
            addCriterion("class_code =", value, "classCode");
            return (Criteria) this;
        }

        public Criteria andClassCodeNotEqualTo(String value) {
            addCriterion("class_code <>", value, "classCode");
            return (Criteria) this;
        }

        public Criteria andClassCodeGreaterThan(String value) {
            addCriterion("class_code >", value, "classCode");
            return (Criteria) this;
        }

        public Criteria andClassCodeGreaterThanOrEqualTo(String value) {
            addCriterion("class_code >=", value, "classCode");
            return (Criteria) this;
        }

        public Criteria andClassCodeLessThan(String value) {
            addCriterion("class_code <", value, "classCode");
            return (Criteria) this;
        }

        public Criteria andClassCodeLessThanOrEqualTo(String value) {
            addCriterion("class_code <=", value, "classCode");
            return (Criteria) this;
        }

        public Criteria andClassCodeLike(String value) {
            addCriterion("class_code like", value, "classCode");
            return (Criteria) this;
        }

        public Criteria andClassCodeNotLike(String value) {
            addCriterion("class_code not like", value, "classCode");
            return (Criteria) this;
        }

        public Criteria andClassCodeIn(List<String> values) {
            addCriterion("class_code in", values, "classCode");
            return (Criteria) this;
        }

        public Criteria andClassCodeNotIn(List<String> values) {
            addCriterion("class_code not in", values, "classCode");
            return (Criteria) this;
        }

        public Criteria andClassCodeBetween(String value1, String value2) {
            addCriterion("class_code between", value1, value2, "classCode");
            return (Criteria) this;
        }

        public Criteria andClassCodeNotBetween(String value1, String value2) {
            addCriterion("class_code not between", value1, value2, "classCode");
            return (Criteria) this;
        }

        public Criteria andCodeValueIsNull() {
            addCriterion("code_value is null");
            return (Criteria) this;
        }

        public Criteria andCodeValueIsNotNull() {
            addCriterion("code_value is not null");
            return (Criteria) this;
        }

        public Criteria andCodeValueEqualTo(String value) {
            addCriterion("code_value =", value, "codeValue");
            return (Criteria) this;
        }

        public Criteria andCodeValueNotEqualTo(String value) {
            addCriterion("code_value <>", value, "codeValue");
            return (Criteria) this;
        }

        public Criteria andCodeValueGreaterThan(String value) {
            addCriterion("code_value >", value, "codeValue");
            return (Criteria) this;
        }

        public Criteria andCodeValueGreaterThanOrEqualTo(String value) {
            addCriterion("code_value >=", value, "codeValue");
            return (Criteria) this;
        }

        public Criteria andCodeValueLessThan(String value) {
            addCriterion("code_value <", value, "codeValue");
            return (Criteria) this;
        }

        public Criteria andCodeValueLessThanOrEqualTo(String value) {
            addCriterion("code_value <=", value, "codeValue");
            return (Criteria) this;
        }

        public Criteria andCodeValueLike(String value) {
            addCriterion("code_value like", value, "codeValue");
            return (Criteria) this;
        }

        public Criteria andCodeValueNotLike(String value) {
            addCriterion("code_value not like", value, "codeValue");
            return (Criteria) this;
        }

        public Criteria andCodeValueIn(List<String> values) {
            addCriterion("code_value in", values, "codeValue");
            return (Criteria) this;
        }

        public Criteria andCodeValueNotIn(List<String> values) {
            addCriterion("code_value not in", values, "codeValue");
            return (Criteria) this;
        }

        public Criteria andCodeValueBetween(String value1, String value2) {
            addCriterion("code_value between", value1, value2, "codeValue");
            return (Criteria) this;
        }

        public Criteria andCodeValueNotBetween(String value1, String value2) {
            addCriterion("code_value not between", value1, value2, "codeValue");
            return (Criteria) this;
        }

        public Criteria andGpCodeMstNameIsNull() {
            addCriterion("gp_code_mst_name is null");
            return (Criteria) this;
        }

        public Criteria andGpCodeMstNameIsNotNull() {
            addCriterion("gp_code_mst_name is not null");
            return (Criteria) this;
        }

        public Criteria andGpCodeMstNameEqualTo(String value) {
            addCriterion("gp_code_mst_name =", value, "gpCodeMstName");
            return (Criteria) this;
        }

        public Criteria andGpCodeMstNameNotEqualTo(String value) {
            addCriterion("gp_code_mst_name <>", value, "gpCodeMstName");
            return (Criteria) this;
        }

        public Criteria andGpCodeMstNameGreaterThan(String value) {
            addCriterion("gp_code_mst_name >", value, "gpCodeMstName");
            return (Criteria) this;
        }

        public Criteria andGpCodeMstNameGreaterThanOrEqualTo(String value) {
            addCriterion("gp_code_mst_name >=", value, "gpCodeMstName");
            return (Criteria) this;
        }

        public Criteria andGpCodeMstNameLessThan(String value) {
            addCriterion("gp_code_mst_name <", value, "gpCodeMstName");
            return (Criteria) this;
        }

        public Criteria andGpCodeMstNameLessThanOrEqualTo(String value) {
            addCriterion("gp_code_mst_name <=", value, "gpCodeMstName");
            return (Criteria) this;
        }

        public Criteria andGpCodeMstNameLike(String value) {
            addCriterion("gp_code_mst_name like", value, "gpCodeMstName");
            return (Criteria) this;
        }

        public Criteria andGpCodeMstNameNotLike(String value) {
            addCriterion("gp_code_mst_name not like", value, "gpCodeMstName");
            return (Criteria) this;
        }

        public Criteria andGpCodeMstNameIn(List<String> values) {
            addCriterion("gp_code_mst_name in", values, "gpCodeMstName");
            return (Criteria) this;
        }

        public Criteria andGpCodeMstNameNotIn(List<String> values) {
            addCriterion("gp_code_mst_name not in", values, "gpCodeMstName");
            return (Criteria) this;
        }

        public Criteria andGpCodeMstNameBetween(String value1, String value2) {
            addCriterion("gp_code_mst_name between", value1, value2, "gpCodeMstName");
            return (Criteria) this;
        }

        public Criteria andGpCodeMstNameNotBetween(String value1, String value2) {
            addCriterion("gp_code_mst_name not between", value1, value2, "gpCodeMstName");
            return (Criteria) this;
        }

        public Criteria andValue1IsNull() {
            addCriterion("value_1 is null");
            return (Criteria) this;
        }

        public Criteria andValue1IsNotNull() {
            addCriterion("value_1 is not null");
            return (Criteria) this;
        }

        public Criteria andValue1EqualTo(String value) {
            addCriterion("value_1 =", value, "value1");
            return (Criteria) this;
        }

        public Criteria andValue1NotEqualTo(String value) {
            addCriterion("value_1 <>", value, "value1");
            return (Criteria) this;
        }

        public Criteria andValue1GreaterThan(String value) {
            addCriterion("value_1 >", value, "value1");
            return (Criteria) this;
        }

        public Criteria andValue1GreaterThanOrEqualTo(String value) {
            addCriterion("value_1 >=", value, "value1");
            return (Criteria) this;
        }

        public Criteria andValue1LessThan(String value) {
            addCriterion("value_1 <", value, "value1");
            return (Criteria) this;
        }

        public Criteria andValue1LessThanOrEqualTo(String value) {
            addCriterion("value_1 <=", value, "value1");
            return (Criteria) this;
        }

        public Criteria andValue1Like(String value) {
            addCriterion("value_1 like", value, "value1");
            return (Criteria) this;
        }

        public Criteria andValue1NotLike(String value) {
            addCriterion("value_1 not like", value, "value1");
            return (Criteria) this;
        }

        public Criteria andValue1In(List<String> values) {
            addCriterion("value_1 in", values, "value1");
            return (Criteria) this;
        }

        public Criteria andValue1NotIn(List<String> values) {
            addCriterion("value_1 not in", values, "value1");
            return (Criteria) this;
        }

        public Criteria andValue1Between(String value1, String value2) {
            addCriterion("value_1 between", value1, value2, "value1");
            return (Criteria) this;
        }

        public Criteria andValue1NotBetween(String value1, String value2) {
            addCriterion("value_1 not between", value1, value2, "value1");
            return (Criteria) this;
        }

        public Criteria andValue2IsNull() {
            addCriterion("value_2 is null");
            return (Criteria) this;
        }

        public Criteria andValue2IsNotNull() {
            addCriterion("value_2 is not null");
            return (Criteria) this;
        }

        public Criteria andValue2EqualTo(String value) {
            addCriterion("value_2 =", value, "value2");
            return (Criteria) this;
        }

        public Criteria andValue2NotEqualTo(String value) {
            addCriterion("value_2 <>", value, "value2");
            return (Criteria) this;
        }

        public Criteria andValue2GreaterThan(String value) {
            addCriterion("value_2 >", value, "value2");
            return (Criteria) this;
        }

        public Criteria andValue2GreaterThanOrEqualTo(String value) {
            addCriterion("value_2 >=", value, "value2");
            return (Criteria) this;
        }

        public Criteria andValue2LessThan(String value) {
            addCriterion("value_2 <", value, "value2");
            return (Criteria) this;
        }

        public Criteria andValue2LessThanOrEqualTo(String value) {
            addCriterion("value_2 <=", value, "value2");
            return (Criteria) this;
        }

        public Criteria andValue2Like(String value) {
            addCriterion("value_2 like", value, "value2");
            return (Criteria) this;
        }

        public Criteria andValue2NotLike(String value) {
            addCriterion("value_2 not like", value, "value2");
            return (Criteria) this;
        }

        public Criteria andValue2In(List<String> values) {
            addCriterion("value_2 in", values, "value2");
            return (Criteria) this;
        }

        public Criteria andValue2NotIn(List<String> values) {
            addCriterion("value_2 not in", values, "value2");
            return (Criteria) this;
        }

        public Criteria andValue2Between(String value1, String value2) {
            addCriterion("value_2 between", value1, value2, "value2");
            return (Criteria) this;
        }

        public Criteria andValue2NotBetween(String value1, String value2) {
            addCriterion("value_2 not between", value1, value2, "value2");
            return (Criteria) this;
        }

        public Criteria andValue3IsNull() {
            addCriterion("value_3 is null");
            return (Criteria) this;
        }

        public Criteria andValue3IsNotNull() {
            addCriterion("value_3 is not null");
            return (Criteria) this;
        }

        public Criteria andValue3EqualTo(String value) {
            addCriterion("value_3 =", value, "value3");
            return (Criteria) this;
        }

        public Criteria andValue3NotEqualTo(String value) {
            addCriterion("value_3 <>", value, "value3");
            return (Criteria) this;
        }

        public Criteria andValue3GreaterThan(String value) {
            addCriterion("value_3 >", value, "value3");
            return (Criteria) this;
        }

        public Criteria andValue3GreaterThanOrEqualTo(String value) {
            addCriterion("value_3 >=", value, "value3");
            return (Criteria) this;
        }

        public Criteria andValue3LessThan(String value) {
            addCriterion("value_3 <", value, "value3");
            return (Criteria) this;
        }

        public Criteria andValue3LessThanOrEqualTo(String value) {
            addCriterion("value_3 <=", value, "value3");
            return (Criteria) this;
        }

        public Criteria andValue3Like(String value) {
            addCriterion("value_3 like", value, "value3");
            return (Criteria) this;
        }

        public Criteria andValue3NotLike(String value) {
            addCriterion("value_3 not like", value, "value3");
            return (Criteria) this;
        }

        public Criteria andValue3In(List<String> values) {
            addCriterion("value_3 in", values, "value3");
            return (Criteria) this;
        }

        public Criteria andValue3NotIn(List<String> values) {
            addCriterion("value_3 not in", values, "value3");
            return (Criteria) this;
        }

        public Criteria andValue3Between(String value1, String value2) {
            addCriterion("value_3 between", value1, value2, "value3");
            return (Criteria) this;
        }

        public Criteria andValue3NotBetween(String value1, String value2) {
            addCriterion("value_3 not between", value1, value2, "value3");
            return (Criteria) this;
        }

        public Criteria andValue4IsNull() {
            addCriterion("value_4 is null");
            return (Criteria) this;
        }

        public Criteria andValue4IsNotNull() {
            addCriterion("value_4 is not null");
            return (Criteria) this;
        }

        public Criteria andValue4EqualTo(String value) {
            addCriterion("value_4 =", value, "value4");
            return (Criteria) this;
        }

        public Criteria andValue4NotEqualTo(String value) {
            addCriterion("value_4 <>", value, "value4");
            return (Criteria) this;
        }

        public Criteria andValue4GreaterThan(String value) {
            addCriterion("value_4 >", value, "value4");
            return (Criteria) this;
        }

        public Criteria andValue4GreaterThanOrEqualTo(String value) {
            addCriterion("value_4 >=", value, "value4");
            return (Criteria) this;
        }

        public Criteria andValue4LessThan(String value) {
            addCriterion("value_4 <", value, "value4");
            return (Criteria) this;
        }

        public Criteria andValue4LessThanOrEqualTo(String value) {
            addCriterion("value_4 <=", value, "value4");
            return (Criteria) this;
        }

        public Criteria andValue4Like(String value) {
            addCriterion("value_4 like", value, "value4");
            return (Criteria) this;
        }

        public Criteria andValue4NotLike(String value) {
            addCriterion("value_4 not like", value, "value4");
            return (Criteria) this;
        }

        public Criteria andValue4In(List<String> values) {
            addCriterion("value_4 in", values, "value4");
            return (Criteria) this;
        }

        public Criteria andValue4NotIn(List<String> values) {
            addCriterion("value_4 not in", values, "value4");
            return (Criteria) this;
        }

        public Criteria andValue4Between(String value1, String value2) {
            addCriterion("value_4 between", value1, value2, "value4");
            return (Criteria) this;
        }

        public Criteria andValue4NotBetween(String value1, String value2) {
            addCriterion("value_4 not between", value1, value2, "value4");
            return (Criteria) this;
        }

        public Criteria andValue5IsNull() {
            addCriterion("value_5 is null");
            return (Criteria) this;
        }

        public Criteria andValue5IsNotNull() {
            addCriterion("value_5 is not null");
            return (Criteria) this;
        }

        public Criteria andValue5EqualTo(String value) {
            addCriterion("value_5 =", value, "value5");
            return (Criteria) this;
        }

        public Criteria andValue5NotEqualTo(String value) {
            addCriterion("value_5 <>", value, "value5");
            return (Criteria) this;
        }

        public Criteria andValue5GreaterThan(String value) {
            addCriterion("value_5 >", value, "value5");
            return (Criteria) this;
        }

        public Criteria andValue5GreaterThanOrEqualTo(String value) {
            addCriterion("value_5 >=", value, "value5");
            return (Criteria) this;
        }

        public Criteria andValue5LessThan(String value) {
            addCriterion("value_5 <", value, "value5");
            return (Criteria) this;
        }

        public Criteria andValue5LessThanOrEqualTo(String value) {
            addCriterion("value_5 <=", value, "value5");
            return (Criteria) this;
        }

        public Criteria andValue5Like(String value) {
            addCriterion("value_5 like", value, "value5");
            return (Criteria) this;
        }

        public Criteria andValue5NotLike(String value) {
            addCriterion("value_5 not like", value, "value5");
            return (Criteria) this;
        }

        public Criteria andValue5In(List<String> values) {
            addCriterion("value_5 in", values, "value5");
            return (Criteria) this;
        }

        public Criteria andValue5NotIn(List<String> values) {
            addCriterion("value_5 not in", values, "value5");
            return (Criteria) this;
        }

        public Criteria andValue5Between(String value1, String value2) {
            addCriterion("value_5 between", value1, value2, "value5");
            return (Criteria) this;
        }

        public Criteria andValue5NotBetween(String value1, String value2) {
            addCriterion("value_5 not between", value1, value2, "value5");
            return (Criteria) this;
        }

        public Criteria andValue6IsNull() {
            addCriterion("value_6 is null");
            return (Criteria) this;
        }

        public Criteria andValue6IsNotNull() {
            addCriterion("value_6 is not null");
            return (Criteria) this;
        }

        public Criteria andValue6EqualTo(String value) {
            addCriterion("value_6 =", value, "value6");
            return (Criteria) this;
        }

        public Criteria andValue6NotEqualTo(String value) {
            addCriterion("value_6 <>", value, "value6");
            return (Criteria) this;
        }

        public Criteria andValue6GreaterThan(String value) {
            addCriterion("value_6 >", value, "value6");
            return (Criteria) this;
        }

        public Criteria andValue6GreaterThanOrEqualTo(String value) {
            addCriterion("value_6 >=", value, "value6");
            return (Criteria) this;
        }

        public Criteria andValue6LessThan(String value) {
            addCriterion("value_6 <", value, "value6");
            return (Criteria) this;
        }

        public Criteria andValue6LessThanOrEqualTo(String value) {
            addCriterion("value_6 <=", value, "value6");
            return (Criteria) this;
        }

        public Criteria andValue6Like(String value) {
            addCriterion("value_6 like", value, "value6");
            return (Criteria) this;
        }

        public Criteria andValue6NotLike(String value) {
            addCriterion("value_6 not like", value, "value6");
            return (Criteria) this;
        }

        public Criteria andValue6In(List<String> values) {
            addCriterion("value_6 in", values, "value6");
            return (Criteria) this;
        }

        public Criteria andValue6NotIn(List<String> values) {
            addCriterion("value_6 not in", values, "value6");
            return (Criteria) this;
        }

        public Criteria andValue6Between(String value1, String value2) {
            addCriterion("value_6 between", value1, value2, "value6");
            return (Criteria) this;
        }

        public Criteria andValue6NotBetween(String value1, String value2) {
            addCriterion("value_6 not between", value1, value2, "value6");
            return (Criteria) this;
        }

        public Criteria andValue7IsNull() {
            addCriterion("value_7 is null");
            return (Criteria) this;
        }

        public Criteria andValue7IsNotNull() {
            addCriterion("value_7 is not null");
            return (Criteria) this;
        }

        public Criteria andValue7EqualTo(String value) {
            addCriterion("value_7 =", value, "value7");
            return (Criteria) this;
        }

        public Criteria andValue7NotEqualTo(String value) {
            addCriterion("value_7 <>", value, "value7");
            return (Criteria) this;
        }

        public Criteria andValue7GreaterThan(String value) {
            addCriterion("value_7 >", value, "value7");
            return (Criteria) this;
        }

        public Criteria andValue7GreaterThanOrEqualTo(String value) {
            addCriterion("value_7 >=", value, "value7");
            return (Criteria) this;
        }

        public Criteria andValue7LessThan(String value) {
            addCriterion("value_7 <", value, "value7");
            return (Criteria) this;
        }

        public Criteria andValue7LessThanOrEqualTo(String value) {
            addCriterion("value_7 <=", value, "value7");
            return (Criteria) this;
        }

        public Criteria andValue7Like(String value) {
            addCriterion("value_7 like", value, "value7");
            return (Criteria) this;
        }

        public Criteria andValue7NotLike(String value) {
            addCriterion("value_7 not like", value, "value7");
            return (Criteria) this;
        }

        public Criteria andValue7In(List<String> values) {
            addCriterion("value_7 in", values, "value7");
            return (Criteria) this;
        }

        public Criteria andValue7NotIn(List<String> values) {
            addCriterion("value_7 not in", values, "value7");
            return (Criteria) this;
        }

        public Criteria andValue7Between(String value1, String value2) {
            addCriterion("value_7 between", value1, value2, "value7");
            return (Criteria) this;
        }

        public Criteria andValue7NotBetween(String value1, String value2) {
            addCriterion("value_7 not between", value1, value2, "value7");
            return (Criteria) this;
        }

        public Criteria andValue8IsNull() {
            addCriterion("value_8 is null");
            return (Criteria) this;
        }

        public Criteria andValue8IsNotNull() {
            addCriterion("value_8 is not null");
            return (Criteria) this;
        }

        public Criteria andValue8EqualTo(String value) {
            addCriterion("value_8 =", value, "value8");
            return (Criteria) this;
        }

        public Criteria andValue8NotEqualTo(String value) {
            addCriterion("value_8 <>", value, "value8");
            return (Criteria) this;
        }

        public Criteria andValue8GreaterThan(String value) {
            addCriterion("value_8 >", value, "value8");
            return (Criteria) this;
        }

        public Criteria andValue8GreaterThanOrEqualTo(String value) {
            addCriterion("value_8 >=", value, "value8");
            return (Criteria) this;
        }

        public Criteria andValue8LessThan(String value) {
            addCriterion("value_8 <", value, "value8");
            return (Criteria) this;
        }

        public Criteria andValue8LessThanOrEqualTo(String value) {
            addCriterion("value_8 <=", value, "value8");
            return (Criteria) this;
        }

        public Criteria andValue8Like(String value) {
            addCriterion("value_8 like", value, "value8");
            return (Criteria) this;
        }

        public Criteria andValue8NotLike(String value) {
            addCriterion("value_8 not like", value, "value8");
            return (Criteria) this;
        }

        public Criteria andValue8In(List<String> values) {
            addCriterion("value_8 in", values, "value8");
            return (Criteria) this;
        }

        public Criteria andValue8NotIn(List<String> values) {
            addCriterion("value_8 not in", values, "value8");
            return (Criteria) this;
        }

        public Criteria andValue8Between(String value1, String value2) {
            addCriterion("value_8 between", value1, value2, "value8");
            return (Criteria) this;
        }

        public Criteria andValue8NotBetween(String value1, String value2) {
            addCriterion("value_8 not between", value1, value2, "value8");
            return (Criteria) this;
        }

        public Criteria andValue9IsNull() {
            addCriterion("value_9 is null");
            return (Criteria) this;
        }

        public Criteria andValue9IsNotNull() {
            addCriterion("value_9 is not null");
            return (Criteria) this;
        }

        public Criteria andValue9EqualTo(String value) {
            addCriterion("value_9 =", value, "value9");
            return (Criteria) this;
        }

        public Criteria andValue9NotEqualTo(String value) {
            addCriterion("value_9 <>", value, "value9");
            return (Criteria) this;
        }

        public Criteria andValue9GreaterThan(String value) {
            addCriterion("value_9 >", value, "value9");
            return (Criteria) this;
        }

        public Criteria andValue9GreaterThanOrEqualTo(String value) {
            addCriterion("value_9 >=", value, "value9");
            return (Criteria) this;
        }

        public Criteria andValue9LessThan(String value) {
            addCriterion("value_9 <", value, "value9");
            return (Criteria) this;
        }

        public Criteria andValue9LessThanOrEqualTo(String value) {
            addCriterion("value_9 <=", value, "value9");
            return (Criteria) this;
        }

        public Criteria andValue9Like(String value) {
            addCriterion("value_9 like", value, "value9");
            return (Criteria) this;
        }

        public Criteria andValue9NotLike(String value) {
            addCriterion("value_9 not like", value, "value9");
            return (Criteria) this;
        }

        public Criteria andValue9In(List<String> values) {
            addCriterion("value_9 in", values, "value9");
            return (Criteria) this;
        }

        public Criteria andValue9NotIn(List<String> values) {
            addCriterion("value_9 not in", values, "value9");
            return (Criteria) this;
        }

        public Criteria andValue9Between(String value1, String value2) {
            addCriterion("value_9 between", value1, value2, "value9");
            return (Criteria) this;
        }

        public Criteria andValue9NotBetween(String value1, String value2) {
            addCriterion("value_9 not between", value1, value2, "value9");
            return (Criteria) this;
        }

        public Criteria andValue10IsNull() {
            addCriterion("value_10 is null");
            return (Criteria) this;
        }

        public Criteria andValue10IsNotNull() {
            addCriterion("value_10 is not null");
            return (Criteria) this;
        }

        public Criteria andValue10EqualTo(String value) {
            addCriterion("value_10 =", value, "value10");
            return (Criteria) this;
        }

        public Criteria andValue10NotEqualTo(String value) {
            addCriterion("value_10 <>", value, "value10");
            return (Criteria) this;
        }

        public Criteria andValue10GreaterThan(String value) {
            addCriterion("value_10 >", value, "value10");
            return (Criteria) this;
        }

        public Criteria andValue10GreaterThanOrEqualTo(String value) {
            addCriterion("value_10 >=", value, "value10");
            return (Criteria) this;
        }

        public Criteria andValue10LessThan(String value) {
            addCriterion("value_10 <", value, "value10");
            return (Criteria) this;
        }

        public Criteria andValue10LessThanOrEqualTo(String value) {
            addCriterion("value_10 <=", value, "value10");
            return (Criteria) this;
        }

        public Criteria andValue10Like(String value) {
            addCriterion("value_10 like", value, "value10");
            return (Criteria) this;
        }

        public Criteria andValue10NotLike(String value) {
            addCriterion("value_10 not like", value, "value10");
            return (Criteria) this;
        }

        public Criteria andValue10In(List<String> values) {
            addCriterion("value_10 in", values, "value10");
            return (Criteria) this;
        }

        public Criteria andValue10NotIn(List<String> values) {
            addCriterion("value_10 not in", values, "value10");
            return (Criteria) this;
        }

        public Criteria andValue10Between(String value1, String value2) {
            addCriterion("value_10 between", value1, value2, "value10");
            return (Criteria) this;
        }

        public Criteria andValue10NotBetween(String value1, String value2) {
            addCriterion("value_10 not between", value1, value2, "value10");
            return (Criteria) this;
        }

        public Criteria andValue11IsNull() {
            addCriterion("value_11 is null");
            return (Criteria) this;
        }

        public Criteria andValue11IsNotNull() {
            addCriterion("value_11 is not null");
            return (Criteria) this;
        }

        public Criteria andValue11EqualTo(String value) {
            addCriterion("value_11 =", value, "value11");
            return (Criteria) this;
        }

        public Criteria andValue11NotEqualTo(String value) {
            addCriterion("value_11 <>", value, "value11");
            return (Criteria) this;
        }

        public Criteria andValue11GreaterThan(String value) {
            addCriterion("value_11 >", value, "value11");
            return (Criteria) this;
        }

        public Criteria andValue11GreaterThanOrEqualTo(String value) {
            addCriterion("value_11 >=", value, "value11");
            return (Criteria) this;
        }

        public Criteria andValue11LessThan(String value) {
            addCriterion("value_11 <", value, "value11");
            return (Criteria) this;
        }

        public Criteria andValue11LessThanOrEqualTo(String value) {
            addCriterion("value_11 <=", value, "value11");
            return (Criteria) this;
        }

        public Criteria andValue11Like(String value) {
            addCriterion("value_11 like", value, "value11");
            return (Criteria) this;
        }

        public Criteria andValue11NotLike(String value) {
            addCriterion("value_11 not like", value, "value11");
            return (Criteria) this;
        }

        public Criteria andValue11In(List<String> values) {
            addCriterion("value_11 in", values, "value11");
            return (Criteria) this;
        }

        public Criteria andValue11NotIn(List<String> values) {
            addCriterion("value_11 not in", values, "value11");
            return (Criteria) this;
        }

        public Criteria andValue11Between(String value1, String value2) {
            addCriterion("value_11 between", value1, value2, "value11");
            return (Criteria) this;
        }

        public Criteria andValue11NotBetween(String value1, String value2) {
            addCriterion("value_11 not between", value1, value2, "value11");
            return (Criteria) this;
        }

        public Criteria andValue12IsNull() {
            addCriterion("value_12 is null");
            return (Criteria) this;
        }

        public Criteria andValue12IsNotNull() {
            addCriterion("value_12 is not null");
            return (Criteria) this;
        }

        public Criteria andValue12EqualTo(String value) {
            addCriterion("value_12 =", value, "value12");
            return (Criteria) this;
        }

        public Criteria andValue12NotEqualTo(String value) {
            addCriterion("value_12 <>", value, "value12");
            return (Criteria) this;
        }

        public Criteria andValue12GreaterThan(String value) {
            addCriterion("value_12 >", value, "value12");
            return (Criteria) this;
        }

        public Criteria andValue12GreaterThanOrEqualTo(String value) {
            addCriterion("value_12 >=", value, "value12");
            return (Criteria) this;
        }

        public Criteria andValue12LessThan(String value) {
            addCriterion("value_12 <", value, "value12");
            return (Criteria) this;
        }

        public Criteria andValue12LessThanOrEqualTo(String value) {
            addCriterion("value_12 <=", value, "value12");
            return (Criteria) this;
        }

        public Criteria andValue12Like(String value) {
            addCriterion("value_12 like", value, "value12");
            return (Criteria) this;
        }

        public Criteria andValue12NotLike(String value) {
            addCriterion("value_12 not like", value, "value12");
            return (Criteria) this;
        }

        public Criteria andValue12In(List<String> values) {
            addCriterion("value_12 in", values, "value12");
            return (Criteria) this;
        }

        public Criteria andValue12NotIn(List<String> values) {
            addCriterion("value_12 not in", values, "value12");
            return (Criteria) this;
        }

        public Criteria andValue12Between(String value1, String value2) {
            addCriterion("value_12 between", value1, value2, "value12");
            return (Criteria) this;
        }

        public Criteria andValue12NotBetween(String value1, String value2) {
            addCriterion("value_12 not between", value1, value2, "value12");
            return (Criteria) this;
        }

        public Criteria andValue13IsNull() {
            addCriterion("value_13 is null");
            return (Criteria) this;
        }

        public Criteria andValue13IsNotNull() {
            addCriterion("value_13 is not null");
            return (Criteria) this;
        }

        public Criteria andValue13EqualTo(String value) {
            addCriterion("value_13 =", value, "value13");
            return (Criteria) this;
        }

        public Criteria andValue13NotEqualTo(String value) {
            addCriterion("value_13 <>", value, "value13");
            return (Criteria) this;
        }

        public Criteria andValue13GreaterThan(String value) {
            addCriterion("value_13 >", value, "value13");
            return (Criteria) this;
        }

        public Criteria andValue13GreaterThanOrEqualTo(String value) {
            addCriterion("value_13 >=", value, "value13");
            return (Criteria) this;
        }

        public Criteria andValue13LessThan(String value) {
            addCriterion("value_13 <", value, "value13");
            return (Criteria) this;
        }

        public Criteria andValue13LessThanOrEqualTo(String value) {
            addCriterion("value_13 <=", value, "value13");
            return (Criteria) this;
        }

        public Criteria andValue13Like(String value) {
            addCriterion("value_13 like", value, "value13");
            return (Criteria) this;
        }

        public Criteria andValue13NotLike(String value) {
            addCriterion("value_13 not like", value, "value13");
            return (Criteria) this;
        }

        public Criteria andValue13In(List<String> values) {
            addCriterion("value_13 in", values, "value13");
            return (Criteria) this;
        }

        public Criteria andValue13NotIn(List<String> values) {
            addCriterion("value_13 not in", values, "value13");
            return (Criteria) this;
        }

        public Criteria andValue13Between(String value1, String value2) {
            addCriterion("value_13 between", value1, value2, "value13");
            return (Criteria) this;
        }

        public Criteria andValue13NotBetween(String value1, String value2) {
            addCriterion("value_13 not between", value1, value2, "value13");
            return (Criteria) this;
        }

        public Criteria andValue14IsNull() {
            addCriterion("value_14 is null");
            return (Criteria) this;
        }

        public Criteria andValue14IsNotNull() {
            addCriterion("value_14 is not null");
            return (Criteria) this;
        }

        public Criteria andValue14EqualTo(String value) {
            addCriterion("value_14 =", value, "value14");
            return (Criteria) this;
        }

        public Criteria andValue14NotEqualTo(String value) {
            addCriterion("value_14 <>", value, "value14");
            return (Criteria) this;
        }

        public Criteria andValue14GreaterThan(String value) {
            addCriterion("value_14 >", value, "value14");
            return (Criteria) this;
        }

        public Criteria andValue14GreaterThanOrEqualTo(String value) {
            addCriterion("value_14 >=", value, "value14");
            return (Criteria) this;
        }

        public Criteria andValue14LessThan(String value) {
            addCriterion("value_14 <", value, "value14");
            return (Criteria) this;
        }

        public Criteria andValue14LessThanOrEqualTo(String value) {
            addCriterion("value_14 <=", value, "value14");
            return (Criteria) this;
        }

        public Criteria andValue14Like(String value) {
            addCriterion("value_14 like", value, "value14");
            return (Criteria) this;
        }

        public Criteria andValue14NotLike(String value) {
            addCriterion("value_14 not like", value, "value14");
            return (Criteria) this;
        }

        public Criteria andValue14In(List<String> values) {
            addCriterion("value_14 in", values, "value14");
            return (Criteria) this;
        }

        public Criteria andValue14NotIn(List<String> values) {
            addCriterion("value_14 not in", values, "value14");
            return (Criteria) this;
        }

        public Criteria andValue14Between(String value1, String value2) {
            addCriterion("value_14 between", value1, value2, "value14");
            return (Criteria) this;
        }

        public Criteria andValue14NotBetween(String value1, String value2) {
            addCriterion("value_14 not between", value1, value2, "value14");
            return (Criteria) this;
        }

        public Criteria andValue15IsNull() {
            addCriterion("value_15 is null");
            return (Criteria) this;
        }

        public Criteria andValue15IsNotNull() {
            addCriterion("value_15 is not null");
            return (Criteria) this;
        }

        public Criteria andValue15EqualTo(String value) {
            addCriterion("value_15 =", value, "value15");
            return (Criteria) this;
        }

        public Criteria andValue15NotEqualTo(String value) {
            addCriterion("value_15 <>", value, "value15");
            return (Criteria) this;
        }

        public Criteria andValue15GreaterThan(String value) {
            addCriterion("value_15 >", value, "value15");
            return (Criteria) this;
        }

        public Criteria andValue15GreaterThanOrEqualTo(String value) {
            addCriterion("value_15 >=", value, "value15");
            return (Criteria) this;
        }

        public Criteria andValue15LessThan(String value) {
            addCriterion("value_15 <", value, "value15");
            return (Criteria) this;
        }

        public Criteria andValue15LessThanOrEqualTo(String value) {
            addCriterion("value_15 <=", value, "value15");
            return (Criteria) this;
        }

        public Criteria andValue15Like(String value) {
            addCriterion("value_15 like", value, "value15");
            return (Criteria) this;
        }

        public Criteria andValue15NotLike(String value) {
            addCriterion("value_15 not like", value, "value15");
            return (Criteria) this;
        }

        public Criteria andValue15In(List<String> values) {
            addCriterion("value_15 in", values, "value15");
            return (Criteria) this;
        }

        public Criteria andValue15NotIn(List<String> values) {
            addCriterion("value_15 not in", values, "value15");
            return (Criteria) this;
        }

        public Criteria andValue15Between(String value1, String value2) {
            addCriterion("value_15 between", value1, value2, "value15");
            return (Criteria) this;
        }

        public Criteria andValue15NotBetween(String value1, String value2) {
            addCriterion("value_15 not between", value1, value2, "value15");
            return (Criteria) this;
        }

        public Criteria andDispOrderIsNull() {
            addCriterion("disp_order is null");
            return (Criteria) this;
        }

        public Criteria andDispOrderIsNotNull() {
            addCriterion("disp_order is not null");
            return (Criteria) this;
        }

        public Criteria andDispOrderEqualTo(String value) {
            addCriterion("disp_order =", value, "dispOrder");
            return (Criteria) this;
        }

        public Criteria andDispOrderNotEqualTo(String value) {
            addCriterion("disp_order <>", value, "dispOrder");
            return (Criteria) this;
        }

        public Criteria andDispOrderGreaterThan(String value) {
            addCriterion("disp_order >", value, "dispOrder");
            return (Criteria) this;
        }

        public Criteria andDispOrderGreaterThanOrEqualTo(String value) {
            addCriterion("disp_order >=", value, "dispOrder");
            return (Criteria) this;
        }

        public Criteria andDispOrderLessThan(String value) {
            addCriterion("disp_order <", value, "dispOrder");
            return (Criteria) this;
        }

        public Criteria andDispOrderLessThanOrEqualTo(String value) {
            addCriterion("disp_order <=", value, "dispOrder");
            return (Criteria) this;
        }

        public Criteria andDispOrderLike(String value) {
            addCriterion("disp_order like", value, "dispOrder");
            return (Criteria) this;
        }

        public Criteria andDispOrderNotLike(String value) {
            addCriterion("disp_order not like", value, "dispOrder");
            return (Criteria) this;
        }

        public Criteria andDispOrderIn(List<String> values) {
            addCriterion("disp_order in", values, "dispOrder");
            return (Criteria) this;
        }

        public Criteria andDispOrderNotIn(List<String> values) {
            addCriterion("disp_order not in", values, "dispOrder");
            return (Criteria) this;
        }

        public Criteria andDispOrderBetween(String value1, String value2) {
            addCriterion("disp_order between", value1, value2, "dispOrder");
            return (Criteria) this;
        }

        public Criteria andDispOrderNotBetween(String value1, String value2) {
            addCriterion("disp_order not between", value1, value2, "dispOrder");
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

        public Criteria andDeleteFlagIsNull() {
            addCriterion("delete_flag is null");
            return (Criteria) this;
        }

        public Criteria andDeleteFlagIsNotNull() {
            addCriterion("delete_flag is not null");
            return (Criteria) this;
        }

        public Criteria andDeleteFlagEqualTo(String value) {
            addCriterion("delete_flag =", value, "deleteFlag");
            return (Criteria) this;
        }

        public Criteria andDeleteFlagNotEqualTo(String value) {
            addCriterion("delete_flag <>", value, "deleteFlag");
            return (Criteria) this;
        }

        public Criteria andDeleteFlagGreaterThan(String value) {
            addCriterion("delete_flag >", value, "deleteFlag");
            return (Criteria) this;
        }

        public Criteria andDeleteFlagGreaterThanOrEqualTo(String value) {
            addCriterion("delete_flag >=", value, "deleteFlag");
            return (Criteria) this;
        }

        public Criteria andDeleteFlagLessThan(String value) {
            addCriterion("delete_flag <", value, "deleteFlag");
            return (Criteria) this;
        }

        public Criteria andDeleteFlagLessThanOrEqualTo(String value) {
            addCriterion("delete_flag <=", value, "deleteFlag");
            return (Criteria) this;
        }

        public Criteria andDeleteFlagLike(String value) {
            addCriterion("delete_flag like", value, "deleteFlag");
            return (Criteria) this;
        }

        public Criteria andDeleteFlagNotLike(String value) {
            addCriterion("delete_flag not like", value, "deleteFlag");
            return (Criteria) this;
        }

        public Criteria andDeleteFlagIn(List<String> values) {
            addCriterion("delete_flag in", values, "deleteFlag");
            return (Criteria) this;
        }

        public Criteria andDeleteFlagNotIn(List<String> values) {
            addCriterion("delete_flag not in", values, "deleteFlag");
            return (Criteria) this;
        }

        public Criteria andDeleteFlagBetween(String value1, String value2) {
            addCriterion("delete_flag between", value1, value2, "deleteFlag");
            return (Criteria) this;
        }

        public Criteria andDeleteFlagNotBetween(String value1, String value2) {
            addCriterion("delete_flag not between", value1, value2, "deleteFlag");
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