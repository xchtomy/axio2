package jp.co.axio.masterMentsetSystem.model;

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

public class VLoginInfoEntityExample {
    protected String orderByClause;

	protected boolean distinct;

	protected List<Criteria> oredCriteria;

	public VLoginInfoEntityExample() {
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

		public Criteria andUserOrganizationHonmuFlagIsNull() {
			addCriterion("user_organization_honmu_flag is null");
			return (Criteria) this;
		}

		public Criteria andUserOrganizationHonmuFlagIsNotNull() {
			addCriterion("user_organization_honmu_flag is not null");
			return (Criteria) this;
		}

		public Criteria andUserOrganizationHonmuFlagEqualTo(String value) {
			addCriterion("user_organization_honmu_flag =", value, "userOrganizationHonmuFlag");
			return (Criteria) this;
		}

		public Criteria andUserOrganizationHonmuFlagNotEqualTo(String value) {
			addCriterion("user_organization_honmu_flag <>", value, "userOrganizationHonmuFlag");
			return (Criteria) this;
		}

		public Criteria andUserOrganizationHonmuFlagGreaterThan(String value) {
			addCriterion("user_organization_honmu_flag >", value, "userOrganizationHonmuFlag");
			return (Criteria) this;
		}

		public Criteria andUserOrganizationHonmuFlagGreaterThanOrEqualTo(String value) {
			addCriterion("user_organization_honmu_flag >=", value, "userOrganizationHonmuFlag");
			return (Criteria) this;
		}

		public Criteria andUserOrganizationHonmuFlagLessThan(String value) {
			addCriterion("user_organization_honmu_flag <", value, "userOrganizationHonmuFlag");
			return (Criteria) this;
		}

		public Criteria andUserOrganizationHonmuFlagLessThanOrEqualTo(String value) {
			addCriterion("user_organization_honmu_flag <=", value, "userOrganizationHonmuFlag");
			return (Criteria) this;
		}

		public Criteria andUserOrganizationHonmuFlagLike(String value) {
			addCriterion("user_organization_honmu_flag like", value, "userOrganizationHonmuFlag");
			return (Criteria) this;
		}

		public Criteria andUserOrganizationHonmuFlagNotLike(String value) {
			addCriterion("user_organization_honmu_flag not like", value, "userOrganizationHonmuFlag");
			return (Criteria) this;
		}

		public Criteria andUserOrganizationHonmuFlagIn(List<String> values) {
			addCriterion("user_organization_honmu_flag in", values, "userOrganizationHonmuFlag");
			return (Criteria) this;
		}

		public Criteria andUserOrganizationHonmuFlagNotIn(List<String> values) {
			addCriterion("user_organization_honmu_flag not in", values, "userOrganizationHonmuFlag");
			return (Criteria) this;
		}

		public Criteria andUserOrganizationHonmuFlagBetween(String value1, String value2) {
			addCriterion("user_organization_honmu_flag between", value1, value2, "userOrganizationHonmuFlag");
			return (Criteria) this;
		}

		public Criteria andUserOrganizationHonmuFlagNotBetween(String value1, String value2) {
			addCriterion("user_organization_honmu_flag not between", value1, value2, "userOrganizationHonmuFlag");
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
			addCriterionForJDBCDate("user_organization_start_date between", value1, value2,
					"userOrganizationStartDate");
			return (Criteria) this;
		}

		public Criteria andUserOrganizationStartDateNotBetween(Date value1, Date value2) {
			addCriterionForJDBCDate("user_organization_start_date not between", value1, value2,
					"userOrganizationStartDate");
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
			addCriterionForJDBCDate("user_organization_end_date not between", value1, value2,
					"userOrganizationEndDate");
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