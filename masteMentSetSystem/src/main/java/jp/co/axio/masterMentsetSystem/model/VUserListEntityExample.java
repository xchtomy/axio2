package jp.co.axio.masterMentsetSystem.model;

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class VUserListEntityExample {
    protected String orderByClause;

    protected boolean distinct;

    protected List<Criteria> oredCriteria;

    public VUserListEntityExample() {
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

        protected void addCriterionForJDBCDate(String condition, Date value, String property) {
            if (value == null) {
                throw new RuntimeException("Value for " + property + " cannot be null");
            }
            addCriterion(condition, new java.sql.Date(value.getTime()), property);
        }

        protected void addCriterionForJDBCDate(String condition, List<Date> values, String property) {
            if (values == null || values.size() == 0) {
                throw new RuntimeException("Value list for " + property + " cannot be null or empty");
            }
            List<java.sql.Date> dateList = new ArrayList<>();
            Iterator<Date> iter = values.iterator();
            while (iter.hasNext()) {
                dateList.add(new java.sql.Date(iter.next().getTime()));
            }
            addCriterion(condition, dateList, property);
        }

        protected void addCriterionForJDBCDate(String condition, Date value1, Date value2, String property) {
            if (value1 == null || value2 == null) {
                throw new RuntimeException("Between values for " + property + " cannot be null");
            }
            addCriterion(condition, new java.sql.Date(value1.getTime()), new java.sql.Date(value2.getTime()), property);
        }

        public Criteria andStateIsNull() {
            addCriterion("state is null");
            return (Criteria) this;
        }

        public Criteria andStateIsNotNull() {
            addCriterion("state is not null");
            return (Criteria) this;
        }

        public Criteria andStateEqualTo(String value) {
            addCriterion("state =", value, "state");
            return (Criteria) this;
        }

        public Criteria andStateNotEqualTo(String value) {
            addCriterion("state <>", value, "state");
            return (Criteria) this;
        }

        public Criteria andStateGreaterThan(String value) {
            addCriterion("state >", value, "state");
            return (Criteria) this;
        }

        public Criteria andStateGreaterThanOrEqualTo(String value) {
            addCriterion("state >=", value, "state");
            return (Criteria) this;
        }

        public Criteria andStateLessThan(String value) {
            addCriterion("state <", value, "state");
            return (Criteria) this;
        }

        public Criteria andStateLessThanOrEqualTo(String value) {
            addCriterion("state <=", value, "state");
            return (Criteria) this;
        }

        public Criteria andStateLike(String value) {
            addCriterion("state like", value, "state");
            return (Criteria) this;
        }

        public Criteria andStateNotLike(String value) {
            addCriterion("state not like", value, "state");
            return (Criteria) this;
        }

        public Criteria andStateIn(List<String> values) {
            addCriterion("state in", values, "state");
            return (Criteria) this;
        }

        public Criteria andStateNotIn(List<String> values) {
            addCriterion("state not in", values, "state");
            return (Criteria) this;
        }

        public Criteria andStateBetween(String value1, String value2) {
            addCriterion("state between", value1, value2, "state");
            return (Criteria) this;
        }

        public Criteria andStateNotBetween(String value1, String value2) {
            addCriterion("state not between", value1, value2, "state");
            return (Criteria) this;
        }

        public Criteria andUserIdIsNull() {
            addCriterion("user_id is null");
            return (Criteria) this;
        }

        public Criteria andUserIdIsNotNull() {
            addCriterion("user_id is not null");
            return (Criteria) this;
        }

        public Criteria andUserIdEqualTo(String value) {
            addCriterion("user_id =", value, "userId");
            return (Criteria) this;
        }

        public Criteria andUserIdNotEqualTo(String value) {
            addCriterion("user_id <>", value, "userId");
            return (Criteria) this;
        }

        public Criteria andUserIdGreaterThan(String value) {
            addCriterion("user_id >", value, "userId");
            return (Criteria) this;
        }

        public Criteria andUserIdGreaterThanOrEqualTo(String value) {
            addCriterion("user_id >=", value, "userId");
            return (Criteria) this;
        }

        public Criteria andUserIdLessThan(String value) {
            addCriterion("user_id <", value, "userId");
            return (Criteria) this;
        }

        public Criteria andUserIdLessThanOrEqualTo(String value) {
            addCriterion("user_id <=", value, "userId");
            return (Criteria) this;
        }

        public Criteria andUserIdLike(String value) {
            addCriterion("user_id like", value, "userId");
            return (Criteria) this;
        }

        public Criteria andUserIdNotLike(String value) {
            addCriterion("user_id not like", value, "userId");
            return (Criteria) this;
        }

        public Criteria andUserIdIn(List<String> values) {
            addCriterion("user_id in", values, "userId");
            return (Criteria) this;
        }

        public Criteria andUserIdNotIn(List<String> values) {
            addCriterion("user_id not in", values, "userId");
            return (Criteria) this;
        }

        public Criteria andUserIdBetween(String value1, String value2) {
            addCriterion("user_id between", value1, value2, "userId");
            return (Criteria) this;
        }

        public Criteria andUserIdNotBetween(String value1, String value2) {
            addCriterion("user_id not between", value1, value2, "userId");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnIsNull() {
            addCriterion("employment_kbn is null");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnIsNotNull() {
            addCriterion("employment_kbn is not null");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnEqualTo(String value) {
            addCriterion("employment_kbn =", value, "employmentKbn");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNotEqualTo(String value) {
            addCriterion("employment_kbn <>", value, "employmentKbn");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnGreaterThan(String value) {
            addCriterion("employment_kbn >", value, "employmentKbn");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnGreaterThanOrEqualTo(String value) {
            addCriterion("employment_kbn >=", value, "employmentKbn");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnLessThan(String value) {
            addCriterion("employment_kbn <", value, "employmentKbn");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnLessThanOrEqualTo(String value) {
            addCriterion("employment_kbn <=", value, "employmentKbn");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnLike(String value) {
            addCriterion("employment_kbn like", value, "employmentKbn");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNotLike(String value) {
            addCriterion("employment_kbn not like", value, "employmentKbn");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnIn(List<String> values) {
            addCriterion("employment_kbn in", values, "employmentKbn");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNotIn(List<String> values) {
            addCriterion("employment_kbn not in", values, "employmentKbn");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnBetween(String value1, String value2) {
            addCriterion("employment_kbn between", value1, value2, "employmentKbn");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNotBetween(String value1, String value2) {
            addCriterion("employment_kbn not between", value1, value2, "employmentKbn");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNameIsNull() {
            addCriterion("employment_kbn_name is null");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNameIsNotNull() {
            addCriterion("employment_kbn_name is not null");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNameEqualTo(String value) {
            addCriterion("employment_kbn_name =", value, "employmentKbnName");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNameNotEqualTo(String value) {
            addCriterion("employment_kbn_name <>", value, "employmentKbnName");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNameGreaterThan(String value) {
            addCriterion("employment_kbn_name >", value, "employmentKbnName");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNameGreaterThanOrEqualTo(String value) {
            addCriterion("employment_kbn_name >=", value, "employmentKbnName");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNameLessThan(String value) {
            addCriterion("employment_kbn_name <", value, "employmentKbnName");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNameLessThanOrEqualTo(String value) {
            addCriterion("employment_kbn_name <=", value, "employmentKbnName");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNameLike(String value) {
            addCriterion("employment_kbn_name like", value, "employmentKbnName");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNameNotLike(String value) {
            addCriterion("employment_kbn_name not like", value, "employmentKbnName");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNameIn(List<String> values) {
            addCriterion("employment_kbn_name in", values, "employmentKbnName");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNameNotIn(List<String> values) {
            addCriterion("employment_kbn_name not in", values, "employmentKbnName");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNameBetween(String value1, String value2) {
            addCriterion("employment_kbn_name between", value1, value2, "employmentKbnName");
            return (Criteria) this;
        }

        public Criteria andEmploymentKbnNameNotBetween(String value1, String value2) {
            addCriterion("employment_kbn_name not between", value1, value2, "employmentKbnName");
            return (Criteria) this;
        }

        public Criteria andUserNameJpIsNull() {
            addCriterion("user_name_jp is null");
            return (Criteria) this;
        }

        public Criteria andUserNameJpIsNotNull() {
            addCriterion("user_name_jp is not null");
            return (Criteria) this;
        }

        public Criteria andUserNameJpEqualTo(String value) {
            addCriterion("user_name_jp =", value, "userNameJp");
            return (Criteria) this;
        }

        public Criteria andUserNameJpNotEqualTo(String value) {
            addCriterion("user_name_jp <>", value, "userNameJp");
            return (Criteria) this;
        }

        public Criteria andUserNameJpGreaterThan(String value) {
            addCriterion("user_name_jp >", value, "userNameJp");
            return (Criteria) this;
        }

        public Criteria andUserNameJpGreaterThanOrEqualTo(String value) {
            addCriterion("user_name_jp >=", value, "userNameJp");
            return (Criteria) this;
        }

        public Criteria andUserNameJpLessThan(String value) {
            addCriterion("user_name_jp <", value, "userNameJp");
            return (Criteria) this;
        }

        public Criteria andUserNameJpLessThanOrEqualTo(String value) {
            addCriterion("user_name_jp <=", value, "userNameJp");
            return (Criteria) this;
        }

        public Criteria andUserNameJpLike(String value) {
            addCriterion("user_name_jp like", value, "userNameJp");
            return (Criteria) this;
        }

        public Criteria andUserNameJpNotLike(String value) {
            addCriterion("user_name_jp not like", value, "userNameJp");
            return (Criteria) this;
        }

        public Criteria andUserNameJpIn(List<String> values) {
            addCriterion("user_name_jp in", values, "userNameJp");
            return (Criteria) this;
        }

        public Criteria andUserNameJpNotIn(List<String> values) {
            addCriterion("user_name_jp not in", values, "userNameJp");
            return (Criteria) this;
        }

        public Criteria andUserNameJpBetween(String value1, String value2) {
            addCriterion("user_name_jp between", value1, value2, "userNameJp");
            return (Criteria) this;
        }

        public Criteria andUserNameJpNotBetween(String value1, String value2) {
            addCriterion("user_name_jp not between", value1, value2, "userNameJp");
            return (Criteria) this;
        }

        public Criteria andUserNameEnIsNull() {
            addCriterion("user_name_en is null");
            return (Criteria) this;
        }

        public Criteria andUserNameEnIsNotNull() {
            addCriterion("user_name_en is not null");
            return (Criteria) this;
        }

        public Criteria andUserNameEnEqualTo(String value) {
            addCriterion("user_name_en =", value, "userNameEn");
            return (Criteria) this;
        }

        public Criteria andUserNameEnNotEqualTo(String value) {
            addCriterion("user_name_en <>", value, "userNameEn");
            return (Criteria) this;
        }

        public Criteria andUserNameEnGreaterThan(String value) {
            addCriterion("user_name_en >", value, "userNameEn");
            return (Criteria) this;
        }

        public Criteria andUserNameEnGreaterThanOrEqualTo(String value) {
            addCriterion("user_name_en >=", value, "userNameEn");
            return (Criteria) this;
        }

        public Criteria andUserNameEnLessThan(String value) {
            addCriterion("user_name_en <", value, "userNameEn");
            return (Criteria) this;
        }

        public Criteria andUserNameEnLessThanOrEqualTo(String value) {
            addCriterion("user_name_en <=", value, "userNameEn");
            return (Criteria) this;
        }

        public Criteria andUserNameEnLike(String value) {
            addCriterion("user_name_en like", value, "userNameEn");
            return (Criteria) this;
        }

        public Criteria andUserNameEnNotLike(String value) {
            addCriterion("user_name_en not like", value, "userNameEn");
            return (Criteria) this;
        }

        public Criteria andUserNameEnIn(List<String> values) {
            addCriterion("user_name_en in", values, "userNameEn");
            return (Criteria) this;
        }

        public Criteria andUserNameEnNotIn(List<String> values) {
            addCriterion("user_name_en not in", values, "userNameEn");
            return (Criteria) this;
        }

        public Criteria andUserNameEnBetween(String value1, String value2) {
            addCriterion("user_name_en between", value1, value2, "userNameEn");
            return (Criteria) this;
        }

        public Criteria andUserNameEnNotBetween(String value1, String value2) {
            addCriterion("user_name_en not between", value1, value2, "userNameEn");
            return (Criteria) this;
        }

        public Criteria andUsernameForSearchIsNull() {
            addCriterion("username_for_search is null");
            return (Criteria) this;
        }

        public Criteria andUsernameForSearchIsNotNull() {
            addCriterion("username_for_search is not null");
            return (Criteria) this;
        }

        public Criteria andUsernameForSearchEqualTo(String value) {
            addCriterion("username_for_search =", value, "usernameForSearch");
            return (Criteria) this;
        }

        public Criteria andUsernameForSearchNotEqualTo(String value) {
            addCriterion("username_for_search <>", value, "usernameForSearch");
            return (Criteria) this;
        }

        public Criteria andUsernameForSearchGreaterThan(String value) {
            addCriterion("username_for_search >", value, "usernameForSearch");
            return (Criteria) this;
        }

        public Criteria andUsernameForSearchGreaterThanOrEqualTo(String value) {
            addCriterion("username_for_search >=", value, "usernameForSearch");
            return (Criteria) this;
        }

        public Criteria andUsernameForSearchLessThan(String value) {
            addCriterion("username_for_search <", value, "usernameForSearch");
            return (Criteria) this;
        }

        public Criteria andUsernameForSearchLessThanOrEqualTo(String value) {
            addCriterion("username_for_search <=", value, "usernameForSearch");
            return (Criteria) this;
        }

        public Criteria andUsernameForSearchLike(String value) {
            addCriterion("username_for_search like", value, "usernameForSearch");
            return (Criteria) this;
        }

        public Criteria andUsernameForSearchNotLike(String value) {
            addCriterion("username_for_search not like", value, "usernameForSearch");
            return (Criteria) this;
        }

        public Criteria andUsernameForSearchIn(List<String> values) {
            addCriterion("username_for_search in", values, "usernameForSearch");
            return (Criteria) this;
        }

        public Criteria andUsernameForSearchNotIn(List<String> values) {
            addCriterion("username_for_search not in", values, "usernameForSearch");
            return (Criteria) this;
        }

        public Criteria andUsernameForSearchBetween(String value1, String value2) {
            addCriterion("username_for_search between", value1, value2, "usernameForSearch");
            return (Criteria) this;
        }

        public Criteria andUsernameForSearchNotBetween(String value1, String value2) {
            addCriterion("username_for_search not between", value1, value2, "usernameForSearch");
            return (Criteria) this;
        }

        public Criteria andCompanyCodeIsNull() {
            addCriterion("company_code is null");
            return (Criteria) this;
        }

        public Criteria andCompanyCodeIsNotNull() {
            addCriterion("company_code is not null");
            return (Criteria) this;
        }

        public Criteria andCompanyCodeEqualTo(String value) {
            addCriterion("company_code =", value, "companyCode");
            return (Criteria) this;
        }

        public Criteria andCompanyCodeNotEqualTo(String value) {
            addCriterion("company_code <>", value, "companyCode");
            return (Criteria) this;
        }

        public Criteria andCompanyCodeGreaterThan(String value) {
            addCriterion("company_code >", value, "companyCode");
            return (Criteria) this;
        }

        public Criteria andCompanyCodeGreaterThanOrEqualTo(String value) {
            addCriterion("company_code >=", value, "companyCode");
            return (Criteria) this;
        }

        public Criteria andCompanyCodeLessThan(String value) {
            addCriterion("company_code <", value, "companyCode");
            return (Criteria) this;
        }

        public Criteria andCompanyCodeLessThanOrEqualTo(String value) {
            addCriterion("company_code <=", value, "companyCode");
            return (Criteria) this;
        }

        public Criteria andCompanyCodeLike(String value) {
            addCriterion("company_code like", value, "companyCode");
            return (Criteria) this;
        }

        public Criteria andCompanyCodeNotLike(String value) {
            addCriterion("company_code not like", value, "companyCode");
            return (Criteria) this;
        }

        public Criteria andCompanyCodeIn(List<String> values) {
            addCriterion("company_code in", values, "companyCode");
            return (Criteria) this;
        }

        public Criteria andCompanyCodeNotIn(List<String> values) {
            addCriterion("company_code not in", values, "companyCode");
            return (Criteria) this;
        }

        public Criteria andCompanyCodeBetween(String value1, String value2) {
            addCriterion("company_code between", value1, value2, "companyCode");
            return (Criteria) this;
        }

        public Criteria andCompanyCodeNotBetween(String value1, String value2) {
            addCriterion("company_code not between", value1, value2, "companyCode");
            return (Criteria) this;
        }

        public Criteria andCompanyNameIsNull() {
            addCriterion("company_name is null");
            return (Criteria) this;
        }

        public Criteria andCompanyNameIsNotNull() {
            addCriterion("company_name is not null");
            return (Criteria) this;
        }

        public Criteria andCompanyNameEqualTo(String value) {
            addCriterion("company_name =", value, "companyName");
            return (Criteria) this;
        }

        public Criteria andCompanyNameNotEqualTo(String value) {
            addCriterion("company_name <>", value, "companyName");
            return (Criteria) this;
        }

        public Criteria andCompanyNameGreaterThan(String value) {
            addCriterion("company_name >", value, "companyName");
            return (Criteria) this;
        }

        public Criteria andCompanyNameGreaterThanOrEqualTo(String value) {
            addCriterion("company_name >=", value, "companyName");
            return (Criteria) this;
        }

        public Criteria andCompanyNameLessThan(String value) {
            addCriterion("company_name <", value, "companyName");
            return (Criteria) this;
        }

        public Criteria andCompanyNameLessThanOrEqualTo(String value) {
            addCriterion("company_name <=", value, "companyName");
            return (Criteria) this;
        }

        public Criteria andCompanyNameLike(String value) {
            addCriterion("company_name like", value, "companyName");
            return (Criteria) this;
        }

        public Criteria andCompanyNameNotLike(String value) {
            addCriterion("company_name not like", value, "companyName");
            return (Criteria) this;
        }

        public Criteria andCompanyNameIn(List<String> values) {
            addCriterion("company_name in", values, "companyName");
            return (Criteria) this;
        }

        public Criteria andCompanyNameNotIn(List<String> values) {
            addCriterion("company_name not in", values, "companyName");
            return (Criteria) this;
        }

        public Criteria andCompanyNameBetween(String value1, String value2) {
            addCriterion("company_name between", value1, value2, "companyName");
            return (Criteria) this;
        }

        public Criteria andCompanyNameNotBetween(String value1, String value2) {
            addCriterion("company_name not between", value1, value2, "companyName");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeIsNull() {
            addCriterion("organization_code is null");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeIsNotNull() {
            addCriterion("organization_code is not null");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeEqualTo(String value) {
            addCriterion("organization_code =", value, "organizationCode");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeNotEqualTo(String value) {
            addCriterion("organization_code <>", value, "organizationCode");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeGreaterThan(String value) {
            addCriterion("organization_code >", value, "organizationCode");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeGreaterThanOrEqualTo(String value) {
            addCriterion("organization_code >=", value, "organizationCode");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeLessThan(String value) {
            addCriterion("organization_code <", value, "organizationCode");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeLessThanOrEqualTo(String value) {
            addCriterion("organization_code <=", value, "organizationCode");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeLike(String value) {
            addCriterion("organization_code like", value, "organizationCode");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeNotLike(String value) {
            addCriterion("organization_code not like", value, "organizationCode");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeIn(List<String> values) {
            addCriterion("organization_code in", values, "organizationCode");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeNotIn(List<String> values) {
            addCriterion("organization_code not in", values, "organizationCode");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeBetween(String value1, String value2) {
            addCriterion("organization_code between", value1, value2, "organizationCode");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeNotBetween(String value1, String value2) {
            addCriterion("organization_code not between", value1, value2, "organizationCode");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameIsNull() {
            addCriterion("organization_name is null");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameIsNotNull() {
            addCriterion("organization_name is not null");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameEqualTo(String value) {
            addCriterion("organization_name =", value, "organizationName");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameNotEqualTo(String value) {
            addCriterion("organization_name <>", value, "organizationName");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameGreaterThan(String value) {
            addCriterion("organization_name >", value, "organizationName");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameGreaterThanOrEqualTo(String value) {
            addCriterion("organization_name >=", value, "organizationName");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameLessThan(String value) {
            addCriterion("organization_name <", value, "organizationName");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameLessThanOrEqualTo(String value) {
            addCriterion("organization_name <=", value, "organizationName");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameLike(String value) {
            addCriterion("organization_name like", value, "organizationName");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameNotLike(String value) {
            addCriterion("organization_name not like", value, "organizationName");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameIn(List<String> values) {
            addCriterion("organization_name in", values, "organizationName");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameNotIn(List<String> values) {
            addCriterion("organization_name not in", values, "organizationName");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameBetween(String value1, String value2) {
            addCriterion("organization_name between", value1, value2, "organizationName");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameNotBetween(String value1, String value2) {
            addCriterion("organization_name not between", value1, value2, "organizationName");
            return (Criteria) this;
        }

        public Criteria andPositionCodeIsNull() {
            addCriterion("position_code is null");
            return (Criteria) this;
        }

        public Criteria andPositionCodeIsNotNull() {
            addCriterion("position_code is not null");
            return (Criteria) this;
        }

        public Criteria andPositionCodeEqualTo(String value) {
            addCriterion("position_code =", value, "positionCode");
            return (Criteria) this;
        }

        public Criteria andPositionCodeNotEqualTo(String value) {
            addCriterion("position_code <>", value, "positionCode");
            return (Criteria) this;
        }

        public Criteria andPositionCodeGreaterThan(String value) {
            addCriterion("position_code >", value, "positionCode");
            return (Criteria) this;
        }

        public Criteria andPositionCodeGreaterThanOrEqualTo(String value) {
            addCriterion("position_code >=", value, "positionCode");
            return (Criteria) this;
        }

        public Criteria andPositionCodeLessThan(String value) {
            addCriterion("position_code <", value, "positionCode");
            return (Criteria) this;
        }

        public Criteria andPositionCodeLessThanOrEqualTo(String value) {
            addCriterion("position_code <=", value, "positionCode");
            return (Criteria) this;
        }

        public Criteria andPositionCodeLike(String value) {
            addCriterion("position_code like", value, "positionCode");
            return (Criteria) this;
        }

        public Criteria andPositionCodeNotLike(String value) {
            addCriterion("position_code not like", value, "positionCode");
            return (Criteria) this;
        }

        public Criteria andPositionCodeIn(List<String> values) {
            addCriterion("position_code in", values, "positionCode");
            return (Criteria) this;
        }

        public Criteria andPositionCodeNotIn(List<String> values) {
            addCriterion("position_code not in", values, "positionCode");
            return (Criteria) this;
        }

        public Criteria andPositionCodeBetween(String value1, String value2) {
            addCriterion("position_code between", value1, value2, "positionCode");
            return (Criteria) this;
        }

        public Criteria andPositionCodeNotBetween(String value1, String value2) {
            addCriterion("position_code not between", value1, value2, "positionCode");
            return (Criteria) this;
        }

        public Criteria andPositionNameIsNull() {
            addCriterion("position_name is null");
            return (Criteria) this;
        }

        public Criteria andPositionNameIsNotNull() {
            addCriterion("position_name is not null");
            return (Criteria) this;
        }

        public Criteria andPositionNameEqualTo(String value) {
            addCriterion("position_name =", value, "positionName");
            return (Criteria) this;
        }

        public Criteria andPositionNameNotEqualTo(String value) {
            addCriterion("position_name <>", value, "positionName");
            return (Criteria) this;
        }

        public Criteria andPositionNameGreaterThan(String value) {
            addCriterion("position_name >", value, "positionName");
            return (Criteria) this;
        }

        public Criteria andPositionNameGreaterThanOrEqualTo(String value) {
            addCriterion("position_name >=", value, "positionName");
            return (Criteria) this;
        }

        public Criteria andPositionNameLessThan(String value) {
            addCriterion("position_name <", value, "positionName");
            return (Criteria) this;
        }

        public Criteria andPositionNameLessThanOrEqualTo(String value) {
            addCriterion("position_name <=", value, "positionName");
            return (Criteria) this;
        }

        public Criteria andPositionNameLike(String value) {
            addCriterion("position_name like", value, "positionName");
            return (Criteria) this;
        }

        public Criteria andPositionNameNotLike(String value) {
            addCriterion("position_name not like", value, "positionName");
            return (Criteria) this;
        }

        public Criteria andPositionNameIn(List<String> values) {
            addCriterion("position_name in", values, "positionName");
            return (Criteria) this;
        }

        public Criteria andPositionNameNotIn(List<String> values) {
            addCriterion("position_name not in", values, "positionName");
            return (Criteria) this;
        }

        public Criteria andPositionNameBetween(String value1, String value2) {
            addCriterion("position_name between", value1, value2, "positionName");
            return (Criteria) this;
        }

        public Criteria andPositionNameNotBetween(String value1, String value2) {
            addCriterion("position_name not between", value1, value2, "positionName");
            return (Criteria) this;
        }

        public Criteria andUserStartDateIsNull() {
            addCriterion("user_start_date is null");
            return (Criteria) this;
        }

        public Criteria andUserStartDateIsNotNull() {
            addCriterion("user_start_date is not null");
            return (Criteria) this;
        }

        public Criteria andUserStartDateEqualTo(Date value) {
            addCriterionForJDBCDate("user_start_date =", value, "userStartDate");
            return (Criteria) this;
        }

        public Criteria andUserStartDateNotEqualTo(Date value) {
            addCriterionForJDBCDate("user_start_date <>", value, "userStartDate");
            return (Criteria) this;
        }

        public Criteria andUserStartDateGreaterThan(Date value) {
            addCriterionForJDBCDate("user_start_date >", value, "userStartDate");
            return (Criteria) this;
        }

        public Criteria andUserStartDateGreaterThanOrEqualTo(Date value) {
            addCriterionForJDBCDate("user_start_date >=", value, "userStartDate");
            return (Criteria) this;
        }

        public Criteria andUserStartDateLessThan(Date value) {
            addCriterionForJDBCDate("user_start_date <", value, "userStartDate");
            return (Criteria) this;
        }

        public Criteria andUserStartDateLessThanOrEqualTo(Date value) {
            addCriterionForJDBCDate("user_start_date <=", value, "userStartDate");
            return (Criteria) this;
        }

        public Criteria andUserStartDateIn(List<Date> values) {
            addCriterionForJDBCDate("user_start_date in", values, "userStartDate");
            return (Criteria) this;
        }

        public Criteria andUserStartDateNotIn(List<Date> values) {
            addCriterionForJDBCDate("user_start_date not in", values, "userStartDate");
            return (Criteria) this;
        }

        public Criteria andUserStartDateBetween(Date value1, Date value2) {
            addCriterionForJDBCDate("user_start_date between", value1, value2, "userStartDate");
            return (Criteria) this;
        }

        public Criteria andUserStartDateNotBetween(Date value1, Date value2) {
            addCriterionForJDBCDate("user_start_date not between", value1, value2, "userStartDate");
            return (Criteria) this;
        }

        public Criteria andUserEndDateIsNull() {
            addCriterion("user_end_date is null");
            return (Criteria) this;
        }

        public Criteria andUserEndDateIsNotNull() {
            addCriterion("user_end_date is not null");
            return (Criteria) this;
        }

        public Criteria andUserEndDateEqualTo(Date value) {
            addCriterionForJDBCDate("user_end_date =", value, "userEndDate");
            return (Criteria) this;
        }

        public Criteria andUserEndDateNotEqualTo(Date value) {
            addCriterionForJDBCDate("user_end_date <>", value, "userEndDate");
            return (Criteria) this;
        }

        public Criteria andUserEndDateGreaterThan(Date value) {
            addCriterionForJDBCDate("user_end_date >", value, "userEndDate");
            return (Criteria) this;
        }

        public Criteria andUserEndDateGreaterThanOrEqualTo(Date value) {
            addCriterionForJDBCDate("user_end_date >=", value, "userEndDate");
            return (Criteria) this;
        }

        public Criteria andUserEndDateLessThan(Date value) {
            addCriterionForJDBCDate("user_end_date <", value, "userEndDate");
            return (Criteria) this;
        }

        public Criteria andUserEndDateLessThanOrEqualTo(Date value) {
            addCriterionForJDBCDate("user_end_date <=", value, "userEndDate");
            return (Criteria) this;
        }

        public Criteria andUserEndDateIn(List<Date> values) {
            addCriterionForJDBCDate("user_end_date in", values, "userEndDate");
            return (Criteria) this;
        }

        public Criteria andUserEndDateNotIn(List<Date> values) {
            addCriterionForJDBCDate("user_end_date not in", values, "userEndDate");
            return (Criteria) this;
        }

        public Criteria andUserEndDateBetween(Date value1, Date value2) {
            addCriterionForJDBCDate("user_end_date between", value1, value2, "userEndDate");
            return (Criteria) this;
        }

        public Criteria andUserEndDateNotBetween(Date value1, Date value2) {
            addCriterionForJDBCDate("user_end_date not between", value1, value2, "userEndDate");
            return (Criteria) this;
        }

        public Criteria andUserInvalidFlagIsNull() {
            addCriterion("user_invalid_flag is null");
            return (Criteria) this;
        }

        public Criteria andUserInvalidFlagIsNotNull() {
            addCriterion("user_invalid_flag is not null");
            return (Criteria) this;
        }

        public Criteria andUserInvalidFlagEqualTo(String value) {
            addCriterion("user_invalid_flag =", value, "userInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserInvalidFlagNotEqualTo(String value) {
            addCriterion("user_invalid_flag <>", value, "userInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserInvalidFlagGreaterThan(String value) {
            addCriterion("user_invalid_flag >", value, "userInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserInvalidFlagGreaterThanOrEqualTo(String value) {
            addCriterion("user_invalid_flag >=", value, "userInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserInvalidFlagLessThan(String value) {
            addCriterion("user_invalid_flag <", value, "userInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserInvalidFlagLessThanOrEqualTo(String value) {
            addCriterion("user_invalid_flag <=", value, "userInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserInvalidFlagLike(String value) {
            addCriterion("user_invalid_flag like", value, "userInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserInvalidFlagNotLike(String value) {
            addCriterion("user_invalid_flag not like", value, "userInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserInvalidFlagIn(List<String> values) {
            addCriterion("user_invalid_flag in", values, "userInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserInvalidFlagNotIn(List<String> values) {
            addCriterion("user_invalid_flag not in", values, "userInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserInvalidFlagBetween(String value1, String value2) {
            addCriterion("user_invalid_flag between", value1, value2, "userInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserInvalidFlagNotBetween(String value1, String value2) {
            addCriterion("user_invalid_flag not between", value1, value2, "userInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationStartDateIsNull() {
            addCriterion("user_organization_start_date is null");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationStartDateIsNotNull() {
            addCriterion("user_organization_start_date is not null");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationStartDateEqualTo(Date value) {
            addCriterionForJDBCDate("user_organization_start_date =", value, "userOrganizationStartDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationStartDateNotEqualTo(Date value) {
            addCriterionForJDBCDate("user_organization_start_date <>", value, "userOrganizationStartDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationStartDateGreaterThan(Date value) {
            addCriterionForJDBCDate("user_organization_start_date >", value, "userOrganizationStartDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationStartDateGreaterThanOrEqualTo(Date value) {
            addCriterionForJDBCDate("user_organization_start_date >=", value, "userOrganizationStartDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationStartDateLessThan(Date value) {
            addCriterionForJDBCDate("user_organization_start_date <", value, "userOrganizationStartDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationStartDateLessThanOrEqualTo(Date value) {
            addCriterionForJDBCDate("user_organization_start_date <=", value, "userOrganizationStartDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationStartDateIn(List<Date> values) {
            addCriterionForJDBCDate("user_organization_start_date in", values, "userOrganizationStartDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationStartDateNotIn(List<Date> values) {
            addCriterionForJDBCDate("user_organization_start_date not in", values, "userOrganizationStartDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationStartDateBetween(Date value1, Date value2) {
            addCriterionForJDBCDate("user_organization_start_date between", value1, value2, "userOrganizationStartDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationStartDateNotBetween(Date value1, Date value2) {
            addCriterionForJDBCDate("user_organization_start_date not between", value1, value2, "userOrganizationStartDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationEndDateIsNull() {
            addCriterion("user_organization_end_date is null");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationEndDateIsNotNull() {
            addCriterion("user_organization_end_date is not null");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationEndDateEqualTo(Date value) {
            addCriterionForJDBCDate("user_organization_end_date =", value, "userOrganizationEndDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationEndDateNotEqualTo(Date value) {
            addCriterionForJDBCDate("user_organization_end_date <>", value, "userOrganizationEndDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationEndDateGreaterThan(Date value) {
            addCriterionForJDBCDate("user_organization_end_date >", value, "userOrganizationEndDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationEndDateGreaterThanOrEqualTo(Date value) {
            addCriterionForJDBCDate("user_organization_end_date >=", value, "userOrganizationEndDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationEndDateLessThan(Date value) {
            addCriterionForJDBCDate("user_organization_end_date <", value, "userOrganizationEndDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationEndDateLessThanOrEqualTo(Date value) {
            addCriterionForJDBCDate("user_organization_end_date <=", value, "userOrganizationEndDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationEndDateIn(List<Date> values) {
            addCriterionForJDBCDate("user_organization_end_date in", values, "userOrganizationEndDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationEndDateNotIn(List<Date> values) {
            addCriterionForJDBCDate("user_organization_end_date not in", values, "userOrganizationEndDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationEndDateBetween(Date value1, Date value2) {
            addCriterionForJDBCDate("user_organization_end_date between", value1, value2, "userOrganizationEndDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationEndDateNotBetween(Date value1, Date value2) {
            addCriterionForJDBCDate("user_organization_end_date not between", value1, value2, "userOrganizationEndDate");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationInvalidFlagIsNull() {
            addCriterion("user_organization_invalid_flag is null");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationInvalidFlagIsNotNull() {
            addCriterion("user_organization_invalid_flag is not null");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationInvalidFlagEqualTo(String value) {
            addCriterion("user_organization_invalid_flag =", value, "userOrganizationInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationInvalidFlagNotEqualTo(String value) {
            addCriterion("user_organization_invalid_flag <>", value, "userOrganizationInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationInvalidFlagGreaterThan(String value) {
            addCriterion("user_organization_invalid_flag >", value, "userOrganizationInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationInvalidFlagGreaterThanOrEqualTo(String value) {
            addCriterion("user_organization_invalid_flag >=", value, "userOrganizationInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationInvalidFlagLessThan(String value) {
            addCriterion("user_organization_invalid_flag <", value, "userOrganizationInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationInvalidFlagLessThanOrEqualTo(String value) {
            addCriterion("user_organization_invalid_flag <=", value, "userOrganizationInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationInvalidFlagLike(String value) {
            addCriterion("user_organization_invalid_flag like", value, "userOrganizationInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationInvalidFlagNotLike(String value) {
            addCriterion("user_organization_invalid_flag not like", value, "userOrganizationInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationInvalidFlagIn(List<String> values) {
            addCriterion("user_organization_invalid_flag in", values, "userOrganizationInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationInvalidFlagNotIn(List<String> values) {
            addCriterion("user_organization_invalid_flag not in", values, "userOrganizationInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationInvalidFlagBetween(String value1, String value2) {
            addCriterion("user_organization_invalid_flag between", value1, value2, "userOrganizationInvalidFlag");
            return (Criteria) this;
        }

        public Criteria andUserOrganizationInvalidFlagNotBetween(String value1, String value2) {
            addCriterion("user_organization_invalid_flag not between", value1, value2, "userOrganizationInvalidFlag");
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