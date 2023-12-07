package jp.co.axio.masterMentsetSystem.model;

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class MOrganizationEntityExample {
    protected String orderByClause;

    protected boolean distinct;

    protected List<Criteria> oredCriteria;

    public MOrganizationEntityExample() {
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

        public Criteria andStartDateIsNull() {
            addCriterion("start_date is null");
            return (Criteria) this;
        }

        public Criteria andStartDateIsNotNull() {
            addCriterion("start_date is not null");
            return (Criteria) this;
        }

        public Criteria andStartDateEqualTo(Date value) {
            addCriterionForJDBCDate("start_date =", value, "startDate");
            return (Criteria) this;
        }

        public Criteria andStartDateNotEqualTo(Date value) {
            addCriterionForJDBCDate("start_date <>", value, "startDate");
            return (Criteria) this;
        }

        public Criteria andStartDateGreaterThan(Date value) {
            addCriterionForJDBCDate("start_date >", value, "startDate");
            return (Criteria) this;
        }

        public Criteria andStartDateGreaterThanOrEqualTo(Date value) {
            addCriterionForJDBCDate("start_date >=", value, "startDate");
            return (Criteria) this;
        }

        public Criteria andStartDateLessThan(Date value) {
            addCriterionForJDBCDate("start_date <", value, "startDate");
            return (Criteria) this;
        }

        public Criteria andStartDateLessThanOrEqualTo(Date value) {
            addCriterionForJDBCDate("start_date <=", value, "startDate");
            return (Criteria) this;
        }

        public Criteria andStartDateIn(List<Date> values) {
            addCriterionForJDBCDate("start_date in", values, "startDate");
            return (Criteria) this;
        }

        public Criteria andStartDateNotIn(List<Date> values) {
            addCriterionForJDBCDate("start_date not in", values, "startDate");
            return (Criteria) this;
        }

        public Criteria andStartDateBetween(Date value1, Date value2) {
            addCriterionForJDBCDate("start_date between", value1, value2, "startDate");
            return (Criteria) this;
        }

        public Criteria andStartDateNotBetween(Date value1, Date value2) {
            addCriterionForJDBCDate("start_date not between", value1, value2, "startDate");
            return (Criteria) this;
        }

        public Criteria andEndDateIsNull() {
            addCriterion("end_date is null");
            return (Criteria) this;
        }

        public Criteria andEndDateIsNotNull() {
            addCriterion("end_date is not null");
            return (Criteria) this;
        }

        public Criteria andEndDateEqualTo(Date value) {
            addCriterionForJDBCDate("end_date =", value, "endDate");
            return (Criteria) this;
        }

        public Criteria andEndDateNotEqualTo(Date value) {
            addCriterionForJDBCDate("end_date <>", value, "endDate");
            return (Criteria) this;
        }

        public Criteria andEndDateGreaterThan(Date value) {
            addCriterionForJDBCDate("end_date >", value, "endDate");
            return (Criteria) this;
        }

        public Criteria andEndDateGreaterThanOrEqualTo(Date value) {
            addCriterionForJDBCDate("end_date >=", value, "endDate");
            return (Criteria) this;
        }

        public Criteria andEndDateLessThan(Date value) {
            addCriterionForJDBCDate("end_date <", value, "endDate");
            return (Criteria) this;
        }

        public Criteria andEndDateLessThanOrEqualTo(Date value) {
            addCriterionForJDBCDate("end_date <=", value, "endDate");
            return (Criteria) this;
        }

        public Criteria andEndDateIn(List<Date> values) {
            addCriterionForJDBCDate("end_date in", values, "endDate");
            return (Criteria) this;
        }

        public Criteria andEndDateNotIn(List<Date> values) {
            addCriterionForJDBCDate("end_date not in", values, "endDate");
            return (Criteria) this;
        }

        public Criteria andEndDateBetween(Date value1, Date value2) {
            addCriterionForJDBCDate("end_date between", value1, value2, "endDate");
            return (Criteria) this;
        }

        public Criteria andEndDateNotBetween(Date value1, Date value2) {
            addCriterionForJDBCDate("end_date not between", value1, value2, "endDate");
            return (Criteria) this;
        }

        public Criteria andInvalidFlagIsNull() {
            addCriterion("invalid_flag is null");
            return (Criteria) this;
        }

        public Criteria andInvalidFlagIsNotNull() {
            addCriterion("invalid_flag is not null");
            return (Criteria) this;
        }

        public Criteria andInvalidFlagEqualTo(String value) {
            addCriterion("invalid_flag =", value, "invalidFlag");
            return (Criteria) this;
        }

        public Criteria andInvalidFlagNotEqualTo(String value) {
            addCriterion("invalid_flag <>", value, "invalidFlag");
            return (Criteria) this;
        }

        public Criteria andInvalidFlagGreaterThan(String value) {
            addCriterion("invalid_flag >", value, "invalidFlag");
            return (Criteria) this;
        }

        public Criteria andInvalidFlagGreaterThanOrEqualTo(String value) {
            addCriterion("invalid_flag >=", value, "invalidFlag");
            return (Criteria) this;
        }

        public Criteria andInvalidFlagLessThan(String value) {
            addCriterion("invalid_flag <", value, "invalidFlag");
            return (Criteria) this;
        }

        public Criteria andInvalidFlagLessThanOrEqualTo(String value) {
            addCriterion("invalid_flag <=", value, "invalidFlag");
            return (Criteria) this;
        }

        public Criteria andInvalidFlagLike(String value) {
            addCriterion("invalid_flag like", value, "invalidFlag");
            return (Criteria) this;
        }

        public Criteria andInvalidFlagNotLike(String value) {
            addCriterion("invalid_flag not like", value, "invalidFlag");
            return (Criteria) this;
        }

        public Criteria andInvalidFlagIn(List<String> values) {
            addCriterion("invalid_flag in", values, "invalidFlag");
            return (Criteria) this;
        }

        public Criteria andInvalidFlagNotIn(List<String> values) {
            addCriterion("invalid_flag not in", values, "invalidFlag");
            return (Criteria) this;
        }

        public Criteria andInvalidFlagBetween(String value1, String value2) {
            addCriterion("invalid_flag between", value1, value2, "invalidFlag");
            return (Criteria) this;
        }

        public Criteria andInvalidFlagNotBetween(String value1, String value2) {
            addCriterion("invalid_flag not between", value1, value2, "invalidFlag");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameEnIsNull() {
            addCriterion("organization_name_en is null");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameEnIsNotNull() {
            addCriterion("organization_name_en is not null");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameEnEqualTo(String value) {
            addCriterion("organization_name_en =", value, "organizationNameEn");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameEnNotEqualTo(String value) {
            addCriterion("organization_name_en <>", value, "organizationNameEn");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameEnGreaterThan(String value) {
            addCriterion("organization_name_en >", value, "organizationNameEn");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameEnGreaterThanOrEqualTo(String value) {
            addCriterion("organization_name_en >=", value, "organizationNameEn");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameEnLessThan(String value) {
            addCriterion("organization_name_en <", value, "organizationNameEn");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameEnLessThanOrEqualTo(String value) {
            addCriterion("organization_name_en <=", value, "organizationNameEn");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameEnLike(String value) {
            addCriterion("organization_name_en like", value, "organizationNameEn");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameEnNotLike(String value) {
            addCriterion("organization_name_en not like", value, "organizationNameEn");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameEnIn(List<String> values) {
            addCriterion("organization_name_en in", values, "organizationNameEn");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameEnNotIn(List<String> values) {
            addCriterion("organization_name_en not in", values, "organizationNameEn");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameEnBetween(String value1, String value2) {
            addCriterion("organization_name_en between", value1, value2, "organizationNameEn");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameEnNotBetween(String value1, String value2) {
            addCriterion("organization_name_en not between", value1, value2, "organizationNameEn");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameJpIsNull() {
            addCriterion("organization_name_jp is null");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameJpIsNotNull() {
            addCriterion("organization_name_jp is not null");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameJpEqualTo(String value) {
            addCriterion("organization_name_jp =", value, "organizationNameJp");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameJpNotEqualTo(String value) {
            addCriterion("organization_name_jp <>", value, "organizationNameJp");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameJpGreaterThan(String value) {
            addCriterion("organization_name_jp >", value, "organizationNameJp");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameJpGreaterThanOrEqualTo(String value) {
            addCriterion("organization_name_jp >=", value, "organizationNameJp");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameJpLessThan(String value) {
            addCriterion("organization_name_jp <", value, "organizationNameJp");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameJpLessThanOrEqualTo(String value) {
            addCriterion("organization_name_jp <=", value, "organizationNameJp");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameJpLike(String value) {
            addCriterion("organization_name_jp like", value, "organizationNameJp");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameJpNotLike(String value) {
            addCriterion("organization_name_jp not like", value, "organizationNameJp");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameJpIn(List<String> values) {
            addCriterion("organization_name_jp in", values, "organizationNameJp");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameJpNotIn(List<String> values) {
            addCriterion("organization_name_jp not in", values, "organizationNameJp");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameJpBetween(String value1, String value2) {
            addCriterion("organization_name_jp between", value1, value2, "organizationNameJp");
            return (Criteria) this;
        }

        public Criteria andOrganizationNameJpNotBetween(String value1, String value2) {
            addCriterion("organization_name_jp not between", value1, value2, "organizationNameJp");
            return (Criteria) this;
        }

        public Criteria andLocationCodeIsNull() {
            addCriterion("location_code is null");
            return (Criteria) this;
        }

        public Criteria andLocationCodeIsNotNull() {
            addCriterion("location_code is not null");
            return (Criteria) this;
        }

        public Criteria andLocationCodeEqualTo(String value) {
            addCriterion("location_code =", value, "locationCode");
            return (Criteria) this;
        }

        public Criteria andLocationCodeNotEqualTo(String value) {
            addCriterion("location_code <>", value, "locationCode");
            return (Criteria) this;
        }

        public Criteria andLocationCodeGreaterThan(String value) {
            addCriterion("location_code >", value, "locationCode");
            return (Criteria) this;
        }

        public Criteria andLocationCodeGreaterThanOrEqualTo(String value) {
            addCriterion("location_code >=", value, "locationCode");
            return (Criteria) this;
        }

        public Criteria andLocationCodeLessThan(String value) {
            addCriterion("location_code <", value, "locationCode");
            return (Criteria) this;
        }

        public Criteria andLocationCodeLessThanOrEqualTo(String value) {
            addCriterion("location_code <=", value, "locationCode");
            return (Criteria) this;
        }

        public Criteria andLocationCodeLike(String value) {
            addCriterion("location_code like", value, "locationCode");
            return (Criteria) this;
        }

        public Criteria andLocationCodeNotLike(String value) {
            addCriterion("location_code not like", value, "locationCode");
            return (Criteria) this;
        }

        public Criteria andLocationCodeIn(List<String> values) {
            addCriterion("location_code in", values, "locationCode");
            return (Criteria) this;
        }

        public Criteria andLocationCodeNotIn(List<String> values) {
            addCriterion("location_code not in", values, "locationCode");
            return (Criteria) this;
        }

        public Criteria andLocationCodeBetween(String value1, String value2) {
            addCriterion("location_code between", value1, value2, "locationCode");
            return (Criteria) this;
        }

        public Criteria andLocationCodeNotBetween(String value1, String value2) {
            addCriterion("location_code not between", value1, value2, "locationCode");
            return (Criteria) this;
        }

        public Criteria andLocationNameEnIsNull() {
            addCriterion("location_name_en is null");
            return (Criteria) this;
        }

        public Criteria andLocationNameEnIsNotNull() {
            addCriterion("location_name_en is not null");
            return (Criteria) this;
        }

        public Criteria andLocationNameEnEqualTo(String value) {
            addCriterion("location_name_en =", value, "locationNameEn");
            return (Criteria) this;
        }

        public Criteria andLocationNameEnNotEqualTo(String value) {
            addCriterion("location_name_en <>", value, "locationNameEn");
            return (Criteria) this;
        }

        public Criteria andLocationNameEnGreaterThan(String value) {
            addCriterion("location_name_en >", value, "locationNameEn");
            return (Criteria) this;
        }

        public Criteria andLocationNameEnGreaterThanOrEqualTo(String value) {
            addCriterion("location_name_en >=", value, "locationNameEn");
            return (Criteria) this;
        }

        public Criteria andLocationNameEnLessThan(String value) {
            addCriterion("location_name_en <", value, "locationNameEn");
            return (Criteria) this;
        }

        public Criteria andLocationNameEnLessThanOrEqualTo(String value) {
            addCriterion("location_name_en <=", value, "locationNameEn");
            return (Criteria) this;
        }

        public Criteria andLocationNameEnLike(String value) {
            addCriterion("location_name_en like", value, "locationNameEn");
            return (Criteria) this;
        }

        public Criteria andLocationNameEnNotLike(String value) {
            addCriterion("location_name_en not like", value, "locationNameEn");
            return (Criteria) this;
        }

        public Criteria andLocationNameEnIn(List<String> values) {
            addCriterion("location_name_en in", values, "locationNameEn");
            return (Criteria) this;
        }

        public Criteria andLocationNameEnNotIn(List<String> values) {
            addCriterion("location_name_en not in", values, "locationNameEn");
            return (Criteria) this;
        }

        public Criteria andLocationNameEnBetween(String value1, String value2) {
            addCriterion("location_name_en between", value1, value2, "locationNameEn");
            return (Criteria) this;
        }

        public Criteria andLocationNameEnNotBetween(String value1, String value2) {
            addCriterion("location_name_en not between", value1, value2, "locationNameEn");
            return (Criteria) this;
        }

        public Criteria andLocationNameJpIsNull() {
            addCriterion("location_name_jp is null");
            return (Criteria) this;
        }

        public Criteria andLocationNameJpIsNotNull() {
            addCriterion("location_name_jp is not null");
            return (Criteria) this;
        }

        public Criteria andLocationNameJpEqualTo(String value) {
            addCriterion("location_name_jp =", value, "locationNameJp");
            return (Criteria) this;
        }

        public Criteria andLocationNameJpNotEqualTo(String value) {
            addCriterion("location_name_jp <>", value, "locationNameJp");
            return (Criteria) this;
        }

        public Criteria andLocationNameJpGreaterThan(String value) {
            addCriterion("location_name_jp >", value, "locationNameJp");
            return (Criteria) this;
        }

        public Criteria andLocationNameJpGreaterThanOrEqualTo(String value) {
            addCriterion("location_name_jp >=", value, "locationNameJp");
            return (Criteria) this;
        }

        public Criteria andLocationNameJpLessThan(String value) {
            addCriterion("location_name_jp <", value, "locationNameJp");
            return (Criteria) this;
        }

        public Criteria andLocationNameJpLessThanOrEqualTo(String value) {
            addCriterion("location_name_jp <=", value, "locationNameJp");
            return (Criteria) this;
        }

        public Criteria andLocationNameJpLike(String value) {
            addCriterion("location_name_jp like", value, "locationNameJp");
            return (Criteria) this;
        }

        public Criteria andLocationNameJpNotLike(String value) {
            addCriterion("location_name_jp not like", value, "locationNameJp");
            return (Criteria) this;
        }

        public Criteria andLocationNameJpIn(List<String> values) {
            addCriterion("location_name_jp in", values, "locationNameJp");
            return (Criteria) this;
        }

        public Criteria andLocationNameJpNotIn(List<String> values) {
            addCriterion("location_name_jp not in", values, "locationNameJp");
            return (Criteria) this;
        }

        public Criteria andLocationNameJpBetween(String value1, String value2) {
            addCriterion("location_name_jp between", value1, value2, "locationNameJp");
            return (Criteria) this;
        }

        public Criteria andLocationNameJpNotBetween(String value1, String value2) {
            addCriterion("location_name_jp not between", value1, value2, "locationNameJp");
            return (Criteria) this;
        }

        public Criteria andOrganizationDispOrderIsNull() {
            addCriterion("organization_disp_order is null");
            return (Criteria) this;
        }

        public Criteria andOrganizationDispOrderIsNotNull() {
            addCriterion("organization_disp_order is not null");
            return (Criteria) this;
        }

        public Criteria andOrganizationDispOrderEqualTo(String value) {
            addCriterion("organization_disp_order =", value, "organizationDispOrder");
            return (Criteria) this;
        }

        public Criteria andOrganizationDispOrderNotEqualTo(String value) {
            addCriterion("organization_disp_order <>", value, "organizationDispOrder");
            return (Criteria) this;
        }

        public Criteria andOrganizationDispOrderGreaterThan(String value) {
            addCriterion("organization_disp_order >", value, "organizationDispOrder");
            return (Criteria) this;
        }

        public Criteria andOrganizationDispOrderGreaterThanOrEqualTo(String value) {
            addCriterion("organization_disp_order >=", value, "organizationDispOrder");
            return (Criteria) this;
        }

        public Criteria andOrganizationDispOrderLessThan(String value) {
            addCriterion("organization_disp_order <", value, "organizationDispOrder");
            return (Criteria) this;
        }

        public Criteria andOrganizationDispOrderLessThanOrEqualTo(String value) {
            addCriterion("organization_disp_order <=", value, "organizationDispOrder");
            return (Criteria) this;
        }

        public Criteria andOrganizationDispOrderLike(String value) {
            addCriterion("organization_disp_order like", value, "organizationDispOrder");
            return (Criteria) this;
        }

        public Criteria andOrganizationDispOrderNotLike(String value) {
            addCriterion("organization_disp_order not like", value, "organizationDispOrder");
            return (Criteria) this;
        }

        public Criteria andOrganizationDispOrderIn(List<String> values) {
            addCriterion("organization_disp_order in", values, "organizationDispOrder");
            return (Criteria) this;
        }

        public Criteria andOrganizationDispOrderNotIn(List<String> values) {
            addCriterion("organization_disp_order not in", values, "organizationDispOrder");
            return (Criteria) this;
        }

        public Criteria andOrganizationDispOrderBetween(String value1, String value2) {
            addCriterion("organization_disp_order between", value1, value2, "organizationDispOrder");
            return (Criteria) this;
        }

        public Criteria andOrganizationDispOrderNotBetween(String value1, String value2) {
            addCriterion("organization_disp_order not between", value1, value2, "organizationDispOrder");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeTopIsNull() {
            addCriterion("organization_code_top is null");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeTopIsNotNull() {
            addCriterion("organization_code_top is not null");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeTopEqualTo(String value) {
            addCriterion("organization_code_top =", value, "organizationCodeTop");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeTopNotEqualTo(String value) {
            addCriterion("organization_code_top <>", value, "organizationCodeTop");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeTopGreaterThan(String value) {
            addCriterion("organization_code_top >", value, "organizationCodeTop");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeTopGreaterThanOrEqualTo(String value) {
            addCriterion("organization_code_top >=", value, "organizationCodeTop");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeTopLessThan(String value) {
            addCriterion("organization_code_top <", value, "organizationCodeTop");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeTopLessThanOrEqualTo(String value) {
            addCriterion("organization_code_top <=", value, "organizationCodeTop");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeTopLike(String value) {
            addCriterion("organization_code_top like", value, "organizationCodeTop");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeTopNotLike(String value) {
            addCriterion("organization_code_top not like", value, "organizationCodeTop");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeTopIn(List<String> values) {
            addCriterion("organization_code_top in", values, "organizationCodeTop");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeTopNotIn(List<String> values) {
            addCriterion("organization_code_top not in", values, "organizationCodeTop");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeTopBetween(String value1, String value2) {
            addCriterion("organization_code_top between", value1, value2, "organizationCodeTop");
            return (Criteria) this;
        }

        public Criteria andOrganizationCodeTopNotBetween(String value1, String value2) {
            addCriterion("organization_code_top not between", value1, value2, "organizationCodeTop");
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