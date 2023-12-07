package jp.co.axio.masterMentsetSystem.model;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class MgpCsvExportDefInfoExample {
    protected String orderByClause;

    protected boolean distinct;

    protected List<Criteria> oredCriteria;

    public MgpCsvExportDefInfoExample() {
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

        public Criteria andSqlNoIsNull() {
            addCriterion("sql_no is null");
            return (Criteria) this;
        }

        public Criteria andSqlNoIsNotNull() {
            addCriterion("sql_no is not null");
            return (Criteria) this;
        }

        public Criteria andSqlNoEqualTo(Integer value) {
            addCriterion("sql_no =", value, "sqlNo");
            return (Criteria) this;
        }

        public Criteria andSqlNoNotEqualTo(Integer value) {
            addCriterion("sql_no <>", value, "sqlNo");
            return (Criteria) this;
        }

        public Criteria andSqlNoGreaterThan(Integer value) {
            addCriterion("sql_no >", value, "sqlNo");
            return (Criteria) this;
        }

        public Criteria andSqlNoGreaterThanOrEqualTo(Integer value) {
            addCriterion("sql_no >=", value, "sqlNo");
            return (Criteria) this;
        }

        public Criteria andSqlNoLessThan(Integer value) {
            addCriterion("sql_no <", value, "sqlNo");
            return (Criteria) this;
        }

        public Criteria andSqlNoLessThanOrEqualTo(Integer value) {
            addCriterion("sql_no <=", value, "sqlNo");
            return (Criteria) this;
        }

        public Criteria andSqlNoIn(List<Integer> values) {
            addCriterion("sql_no in", values, "sqlNo");
            return (Criteria) this;
        }

        public Criteria andSqlNoNotIn(List<Integer> values) {
            addCriterion("sql_no not in", values, "sqlNo");
            return (Criteria) this;
        }

        public Criteria andSqlNoBetween(Integer value1, Integer value2) {
            addCriterion("sql_no between", value1, value2, "sqlNo");
            return (Criteria) this;
        }

        public Criteria andSqlNoNotBetween(Integer value1, Integer value2) {
            addCriterion("sql_no not between", value1, value2, "sqlNo");
            return (Criteria) this;
        }

        public Criteria andSystemIdIsNull() {
            addCriterion("system_id is null");
            return (Criteria) this;
        }

        public Criteria andSystemIdIsNotNull() {
            addCriterion("system_id is not null");
            return (Criteria) this;
        }

        public Criteria andSystemIdEqualTo(String value) {
            addCriterion("system_id =", value, "systemId");
            return (Criteria) this;
        }

        public Criteria andSystemIdNotEqualTo(String value) {
            addCriterion("system_id <>", value, "systemId");
            return (Criteria) this;
        }

        public Criteria andSystemIdGreaterThan(String value) {
            addCriterion("system_id >", value, "systemId");
            return (Criteria) this;
        }

        public Criteria andSystemIdGreaterThanOrEqualTo(String value) {
            addCriterion("system_id >=", value, "systemId");
            return (Criteria) this;
        }

        public Criteria andSystemIdLessThan(String value) {
            addCriterion("system_id <", value, "systemId");
            return (Criteria) this;
        }

        public Criteria andSystemIdLessThanOrEqualTo(String value) {
            addCriterion("system_id <=", value, "systemId");
            return (Criteria) this;
        }

        public Criteria andSystemIdLike(String value) {
            addCriterion("system_id like", value, "systemId");
            return (Criteria) this;
        }

        public Criteria andSystemIdNotLike(String value) {
            addCriterion("system_id not like", value, "systemId");
            return (Criteria) this;
        }

        public Criteria andSystemIdIn(List<String> values) {
            addCriterion("system_id in", values, "systemId");
            return (Criteria) this;
        }

        public Criteria andSystemIdNotIn(List<String> values) {
            addCriterion("system_id not in", values, "systemId");
            return (Criteria) this;
        }

        public Criteria andSystemIdBetween(String value1, String value2) {
            addCriterion("system_id between", value1, value2, "systemId");
            return (Criteria) this;
        }

        public Criteria andSystemIdNotBetween(String value1, String value2) {
            addCriterion("system_id not between", value1, value2, "systemId");
            return (Criteria) this;
        }

        public Criteria andSqlRegisterNameIsNull() {
            addCriterion("sql_register_name is null");
            return (Criteria) this;
        }

        public Criteria andSqlRegisterNameIsNotNull() {
            addCriterion("sql_register_name is not null");
            return (Criteria) this;
        }

        public Criteria andSqlRegisterNameEqualTo(String value) {
            addCriterion("sql_register_name =", value, "sqlRegisterName");
            return (Criteria) this;
        }

        public Criteria andSqlRegisterNameNotEqualTo(String value) {
            addCriterion("sql_register_name <>", value, "sqlRegisterName");
            return (Criteria) this;
        }

        public Criteria andSqlRegisterNameGreaterThan(String value) {
            addCriterion("sql_register_name >", value, "sqlRegisterName");
            return (Criteria) this;
        }

        public Criteria andSqlRegisterNameGreaterThanOrEqualTo(String value) {
            addCriterion("sql_register_name >=", value, "sqlRegisterName");
            return (Criteria) this;
        }

        public Criteria andSqlRegisterNameLessThan(String value) {
            addCriterion("sql_register_name <", value, "sqlRegisterName");
            return (Criteria) this;
        }

        public Criteria andSqlRegisterNameLessThanOrEqualTo(String value) {
            addCriterion("sql_register_name <=", value, "sqlRegisterName");
            return (Criteria) this;
        }

        public Criteria andSqlRegisterNameLike(String value) {
            addCriterion("sql_register_name like", value, "sqlRegisterName");
            return (Criteria) this;
        }

        public Criteria andSqlRegisterNameNotLike(String value) {
            addCriterion("sql_register_name not like", value, "sqlRegisterName");
            return (Criteria) this;
        }

        public Criteria andSqlRegisterNameIn(List<String> values) {
            addCriterion("sql_register_name in", values, "sqlRegisterName");
            return (Criteria) this;
        }

        public Criteria andSqlRegisterNameNotIn(List<String> values) {
            addCriterion("sql_register_name not in", values, "sqlRegisterName");
            return (Criteria) this;
        }

        public Criteria andSqlRegisterNameBetween(String value1, String value2) {
            addCriterion("sql_register_name between", value1, value2, "sqlRegisterName");
            return (Criteria) this;
        }

        public Criteria andSqlRegisterNameNotBetween(String value1, String value2) {
            addCriterion("sql_register_name not between", value1, value2, "sqlRegisterName");
            return (Criteria) this;
        }

        public Criteria andValidFlagIsNull() {
            addCriterion("valid_flag is null");
            return (Criteria) this;
        }

        public Criteria andValidFlagIsNotNull() {
            addCriterion("valid_flag is not null");
            return (Criteria) this;
        }

        public Criteria andValidFlagEqualTo(String value) {
            addCriterion("valid_flag =", value, "validFlag");
            return (Criteria) this;
        }

        public Criteria andValidFlagNotEqualTo(String value) {
            addCriterion("valid_flag <>", value, "validFlag");
            return (Criteria) this;
        }

        public Criteria andValidFlagGreaterThan(String value) {
            addCriterion("valid_flag >", value, "validFlag");
            return (Criteria) this;
        }

        public Criteria andValidFlagGreaterThanOrEqualTo(String value) {
            addCriterion("valid_flag >=", value, "validFlag");
            return (Criteria) this;
        }

        public Criteria andValidFlagLessThan(String value) {
            addCriterion("valid_flag <", value, "validFlag");
            return (Criteria) this;
        }

        public Criteria andValidFlagLessThanOrEqualTo(String value) {
            addCriterion("valid_flag <=", value, "validFlag");
            return (Criteria) this;
        }

        public Criteria andValidFlagLike(String value) {
            addCriterion("valid_flag like", value, "validFlag");
            return (Criteria) this;
        }

        public Criteria andValidFlagNotLike(String value) {
            addCriterion("valid_flag not like", value, "validFlag");
            return (Criteria) this;
        }

        public Criteria andValidFlagIn(List<String> values) {
            addCriterion("valid_flag in", values, "validFlag");
            return (Criteria) this;
        }

        public Criteria andValidFlagNotIn(List<String> values) {
            addCriterion("valid_flag not in", values, "validFlag");
            return (Criteria) this;
        }

        public Criteria andValidFlagBetween(String value1, String value2) {
            addCriterion("valid_flag between", value1, value2, "validFlag");
            return (Criteria) this;
        }

        public Criteria andValidFlagNotBetween(String value1, String value2) {
            addCriterion("valid_flag not between", value1, value2, "validFlag");
            return (Criteria) this;
        }

        public Criteria andFileSavePathIsNull() {
            addCriterion("file_save_path is null");
            return (Criteria) this;
        }

        public Criteria andFileSavePathIsNotNull() {
            addCriterion("file_save_path is not null");
            return (Criteria) this;
        }

        public Criteria andFileSavePathEqualTo(String value) {
            addCriterion("file_save_path =", value, "fileSavePath");
            return (Criteria) this;
        }

        public Criteria andFileSavePathNotEqualTo(String value) {
            addCriterion("file_save_path <>", value, "fileSavePath");
            return (Criteria) this;
        }

        public Criteria andFileSavePathGreaterThan(String value) {
            addCriterion("file_save_path >", value, "fileSavePath");
            return (Criteria) this;
        }

        public Criteria andFileSavePathGreaterThanOrEqualTo(String value) {
            addCriterion("file_save_path >=", value, "fileSavePath");
            return (Criteria) this;
        }

        public Criteria andFileSavePathLessThan(String value) {
            addCriterion("file_save_path <", value, "fileSavePath");
            return (Criteria) this;
        }

        public Criteria andFileSavePathLessThanOrEqualTo(String value) {
            addCriterion("file_save_path <=", value, "fileSavePath");
            return (Criteria) this;
        }

        public Criteria andFileSavePathLike(String value) {
            addCriterion("file_save_path like", value, "fileSavePath");
            return (Criteria) this;
        }

        public Criteria andFileSavePathNotLike(String value) {
            addCriterion("file_save_path not like", value, "fileSavePath");
            return (Criteria) this;
        }

        public Criteria andFileSavePathIn(List<String> values) {
            addCriterion("file_save_path in", values, "fileSavePath");
            return (Criteria) this;
        }

        public Criteria andFileSavePathNotIn(List<String> values) {
            addCriterion("file_save_path not in", values, "fileSavePath");
            return (Criteria) this;
        }

        public Criteria andFileSavePathBetween(String value1, String value2) {
            addCriterion("file_save_path between", value1, value2, "fileSavePath");
            return (Criteria) this;
        }

        public Criteria andFileSavePathNotBetween(String value1, String value2) {
            addCriterion("file_save_path not between", value1, value2, "fileSavePath");
            return (Criteria) this;
        }

        public Criteria andFileNameIsNull() {
            addCriterion("file_name is null");
            return (Criteria) this;
        }

        public Criteria andFileNameIsNotNull() {
            addCriterion("file_name is not null");
            return (Criteria) this;
        }

        public Criteria andFileNameEqualTo(String value) {
            addCriterion("file_name =", value, "fileName");
            return (Criteria) this;
        }

        public Criteria andFileNameNotEqualTo(String value) {
            addCriterion("file_name <>", value, "fileName");
            return (Criteria) this;
        }

        public Criteria andFileNameGreaterThan(String value) {
            addCriterion("file_name >", value, "fileName");
            return (Criteria) this;
        }

        public Criteria andFileNameGreaterThanOrEqualTo(String value) {
            addCriterion("file_name >=", value, "fileName");
            return (Criteria) this;
        }

        public Criteria andFileNameLessThan(String value) {
            addCriterion("file_name <", value, "fileName");
            return (Criteria) this;
        }

        public Criteria andFileNameLessThanOrEqualTo(String value) {
            addCriterion("file_name <=", value, "fileName");
            return (Criteria) this;
        }

        public Criteria andFileNameLike(String value) {
            addCriterion("file_name like", value, "fileName");
            return (Criteria) this;
        }

        public Criteria andFileNameNotLike(String value) {
            addCriterion("file_name not like", value, "fileName");
            return (Criteria) this;
        }

        public Criteria andFileNameIn(List<String> values) {
            addCriterion("file_name in", values, "fileName");
            return (Criteria) this;
        }

        public Criteria andFileNameNotIn(List<String> values) {
            addCriterion("file_name not in", values, "fileName");
            return (Criteria) this;
        }

        public Criteria andFileNameBetween(String value1, String value2) {
            addCriterion("file_name between", value1, value2, "fileName");
            return (Criteria) this;
        }

        public Criteria andFileNameNotBetween(String value1, String value2) {
            addCriterion("file_name not between", value1, value2, "fileName");
            return (Criteria) this;
        }

        public Criteria andFileClassIsNull() {
            addCriterion("file_class is null");
            return (Criteria) this;
        }

        public Criteria andFileClassIsNotNull() {
            addCriterion("file_class is not null");
            return (Criteria) this;
        }

        public Criteria andFileClassEqualTo(String value) {
            addCriterion("file_class =", value, "fileClass");
            return (Criteria) this;
        }

        public Criteria andFileClassNotEqualTo(String value) {
            addCriterion("file_class <>", value, "fileClass");
            return (Criteria) this;
        }

        public Criteria andFileClassGreaterThan(String value) {
            addCriterion("file_class >", value, "fileClass");
            return (Criteria) this;
        }

        public Criteria andFileClassGreaterThanOrEqualTo(String value) {
            addCriterion("file_class >=", value, "fileClass");
            return (Criteria) this;
        }

        public Criteria andFileClassLessThan(String value) {
            addCriterion("file_class <", value, "fileClass");
            return (Criteria) this;
        }

        public Criteria andFileClassLessThanOrEqualTo(String value) {
            addCriterion("file_class <=", value, "fileClass");
            return (Criteria) this;
        }

        public Criteria andFileClassLike(String value) {
            addCriterion("file_class like", value, "fileClass");
            return (Criteria) this;
        }

        public Criteria andFileClassNotLike(String value) {
            addCriterion("file_class not like", value, "fileClass");
            return (Criteria) this;
        }

        public Criteria andFileClassIn(List<String> values) {
            addCriterion("file_class in", values, "fileClass");
            return (Criteria) this;
        }

        public Criteria andFileClassNotIn(List<String> values) {
            addCriterion("file_class not in", values, "fileClass");
            return (Criteria) this;
        }

        public Criteria andFileClassBetween(String value1, String value2) {
            addCriterion("file_class between", value1, value2, "fileClass");
            return (Criteria) this;
        }

        public Criteria andFileClassNotBetween(String value1, String value2) {
            addCriterion("file_class not between", value1, value2, "fileClass");
            return (Criteria) this;
        }

        public Criteria andFileNamingClassIsNull() {
            addCriterion("file_naming_class is null");
            return (Criteria) this;
        }

        public Criteria andFileNamingClassIsNotNull() {
            addCriterion("file_naming_class is not null");
            return (Criteria) this;
        }

        public Criteria andFileNamingClassEqualTo(String value) {
            addCriterion("file_naming_class =", value, "fileNamingClass");
            return (Criteria) this;
        }

        public Criteria andFileNamingClassNotEqualTo(String value) {
            addCriterion("file_naming_class <>", value, "fileNamingClass");
            return (Criteria) this;
        }

        public Criteria andFileNamingClassGreaterThan(String value) {
            addCriterion("file_naming_class >", value, "fileNamingClass");
            return (Criteria) this;
        }

        public Criteria andFileNamingClassGreaterThanOrEqualTo(String value) {
            addCriterion("file_naming_class >=", value, "fileNamingClass");
            return (Criteria) this;
        }

        public Criteria andFileNamingClassLessThan(String value) {
            addCriterion("file_naming_class <", value, "fileNamingClass");
            return (Criteria) this;
        }

        public Criteria andFileNamingClassLessThanOrEqualTo(String value) {
            addCriterion("file_naming_class <=", value, "fileNamingClass");
            return (Criteria) this;
        }

        public Criteria andFileNamingClassLike(String value) {
            addCriterion("file_naming_class like", value, "fileNamingClass");
            return (Criteria) this;
        }

        public Criteria andFileNamingClassNotLike(String value) {
            addCriterion("file_naming_class not like", value, "fileNamingClass");
            return (Criteria) this;
        }

        public Criteria andFileNamingClassIn(List<String> values) {
            addCriterion("file_naming_class in", values, "fileNamingClass");
            return (Criteria) this;
        }

        public Criteria andFileNamingClassNotIn(List<String> values) {
            addCriterion("file_naming_class not in", values, "fileNamingClass");
            return (Criteria) this;
        }

        public Criteria andFileNamingClassBetween(String value1, String value2) {
            addCriterion("file_naming_class between", value1, value2, "fileNamingClass");
            return (Criteria) this;
        }

        public Criteria andFileNamingClassNotBetween(String value1, String value2) {
            addCriterion("file_naming_class not between", value1, value2, "fileNamingClass");
            return (Criteria) this;
        }

        public Criteria andStrCodeIsNull() {
            addCriterion("str_code is null");
            return (Criteria) this;
        }

        public Criteria andStrCodeIsNotNull() {
            addCriterion("str_code is not null");
            return (Criteria) this;
        }

        public Criteria andStrCodeEqualTo(String value) {
            addCriterion("str_code =", value, "strCode");
            return (Criteria) this;
        }

        public Criteria andStrCodeNotEqualTo(String value) {
            addCriterion("str_code <>", value, "strCode");
            return (Criteria) this;
        }

        public Criteria andStrCodeGreaterThan(String value) {
            addCriterion("str_code >", value, "strCode");
            return (Criteria) this;
        }

        public Criteria andStrCodeGreaterThanOrEqualTo(String value) {
            addCriterion("str_code >=", value, "strCode");
            return (Criteria) this;
        }

        public Criteria andStrCodeLessThan(String value) {
            addCriterion("str_code <", value, "strCode");
            return (Criteria) this;
        }

        public Criteria andStrCodeLessThanOrEqualTo(String value) {
            addCriterion("str_code <=", value, "strCode");
            return (Criteria) this;
        }

        public Criteria andStrCodeLike(String value) {
            addCriterion("str_code like", value, "strCode");
            return (Criteria) this;
        }

        public Criteria andStrCodeNotLike(String value) {
            addCriterion("str_code not like", value, "strCode");
            return (Criteria) this;
        }

        public Criteria andStrCodeIn(List<String> values) {
            addCriterion("str_code in", values, "strCode");
            return (Criteria) this;
        }

        public Criteria andStrCodeNotIn(List<String> values) {
            addCriterion("str_code not in", values, "strCode");
            return (Criteria) this;
        }

        public Criteria andStrCodeBetween(String value1, String value2) {
            addCriterion("str_code between", value1, value2, "strCode");
            return (Criteria) this;
        }

        public Criteria andStrCodeNotBetween(String value1, String value2) {
            addCriterion("str_code not between", value1, value2, "strCode");
            return (Criteria) this;
        }

        public Criteria andDelimiterClassIsNull() {
            addCriterion("delimiter_class is null");
            return (Criteria) this;
        }

        public Criteria andDelimiterClassIsNotNull() {
            addCriterion("delimiter_class is not null");
            return (Criteria) this;
        }

        public Criteria andDelimiterClassEqualTo(String value) {
            addCriterion("delimiter_class =", value, "delimiterClass");
            return (Criteria) this;
        }

        public Criteria andDelimiterClassNotEqualTo(String value) {
            addCriterion("delimiter_class <>", value, "delimiterClass");
            return (Criteria) this;
        }

        public Criteria andDelimiterClassGreaterThan(String value) {
            addCriterion("delimiter_class >", value, "delimiterClass");
            return (Criteria) this;
        }

        public Criteria andDelimiterClassGreaterThanOrEqualTo(String value) {
            addCriterion("delimiter_class >=", value, "delimiterClass");
            return (Criteria) this;
        }

        public Criteria andDelimiterClassLessThan(String value) {
            addCriterion("delimiter_class <", value, "delimiterClass");
            return (Criteria) this;
        }

        public Criteria andDelimiterClassLessThanOrEqualTo(String value) {
            addCriterion("delimiter_class <=", value, "delimiterClass");
            return (Criteria) this;
        }

        public Criteria andDelimiterClassLike(String value) {
            addCriterion("delimiter_class like", value, "delimiterClass");
            return (Criteria) this;
        }

        public Criteria andDelimiterClassNotLike(String value) {
            addCriterion("delimiter_class not like", value, "delimiterClass");
            return (Criteria) this;
        }

        public Criteria andDelimiterClassIn(List<String> values) {
            addCriterion("delimiter_class in", values, "delimiterClass");
            return (Criteria) this;
        }

        public Criteria andDelimiterClassNotIn(List<String> values) {
            addCriterion("delimiter_class not in", values, "delimiterClass");
            return (Criteria) this;
        }

        public Criteria andDelimiterClassBetween(String value1, String value2) {
            addCriterion("delimiter_class between", value1, value2, "delimiterClass");
            return (Criteria) this;
        }

        public Criteria andDelimiterClassNotBetween(String value1, String value2) {
            addCriterion("delimiter_class not between", value1, value2, "delimiterClass");
            return (Criteria) this;
        }

        public Criteria andFileCodeFormatClassIsNull() {
            addCriterion("file_code_format_class is null");
            return (Criteria) this;
        }

        public Criteria andFileCodeFormatClassIsNotNull() {
            addCriterion("file_code_format_class is not null");
            return (Criteria) this;
        }

        public Criteria andFileCodeFormatClassEqualTo(String value) {
            addCriterion("file_code_format_class =", value, "fileCodeFormatClass");
            return (Criteria) this;
        }

        public Criteria andFileCodeFormatClassNotEqualTo(String value) {
            addCriterion("file_code_format_class <>", value, "fileCodeFormatClass");
            return (Criteria) this;
        }

        public Criteria andFileCodeFormatClassGreaterThan(String value) {
            addCriterion("file_code_format_class >", value, "fileCodeFormatClass");
            return (Criteria) this;
        }

        public Criteria andFileCodeFormatClassGreaterThanOrEqualTo(String value) {
            addCriterion("file_code_format_class >=", value, "fileCodeFormatClass");
            return (Criteria) this;
        }

        public Criteria andFileCodeFormatClassLessThan(String value) {
            addCriterion("file_code_format_class <", value, "fileCodeFormatClass");
            return (Criteria) this;
        }

        public Criteria andFileCodeFormatClassLessThanOrEqualTo(String value) {
            addCriterion("file_code_format_class <=", value, "fileCodeFormatClass");
            return (Criteria) this;
        }

        public Criteria andFileCodeFormatClassLike(String value) {
            addCriterion("file_code_format_class like", value, "fileCodeFormatClass");
            return (Criteria) this;
        }

        public Criteria andFileCodeFormatClassNotLike(String value) {
            addCriterion("file_code_format_class not like", value, "fileCodeFormatClass");
            return (Criteria) this;
        }

        public Criteria andFileCodeFormatClassIn(List<String> values) {
            addCriterion("file_code_format_class in", values, "fileCodeFormatClass");
            return (Criteria) this;
        }

        public Criteria andFileCodeFormatClassNotIn(List<String> values) {
            addCriterion("file_code_format_class not in", values, "fileCodeFormatClass");
            return (Criteria) this;
        }

        public Criteria andFileCodeFormatClassBetween(String value1, String value2) {
            addCriterion("file_code_format_class between", value1, value2, "fileCodeFormatClass");
            return (Criteria) this;
        }

        public Criteria andFileCodeFormatClassNotBetween(String value1, String value2) {
            addCriterion("file_code_format_class not between", value1, value2, "fileCodeFormatClass");
            return (Criteria) this;
        }

        public Criteria andSeparationDefClassIsNull() {
            addCriterion("separation_def_class is null");
            return (Criteria) this;
        }

        public Criteria andSeparationDefClassIsNotNull() {
            addCriterion("separation_def_class is not null");
            return (Criteria) this;
        }

        public Criteria andSeparationDefClassEqualTo(String value) {
            addCriterion("separation_def_class =", value, "separationDefClass");
            return (Criteria) this;
        }

        public Criteria andSeparationDefClassNotEqualTo(String value) {
            addCriterion("separation_def_class <>", value, "separationDefClass");
            return (Criteria) this;
        }

        public Criteria andSeparationDefClassGreaterThan(String value) {
            addCriterion("separation_def_class >", value, "separationDefClass");
            return (Criteria) this;
        }

        public Criteria andSeparationDefClassGreaterThanOrEqualTo(String value) {
            addCriterion("separation_def_class >=", value, "separationDefClass");
            return (Criteria) this;
        }

        public Criteria andSeparationDefClassLessThan(String value) {
            addCriterion("separation_def_class <", value, "separationDefClass");
            return (Criteria) this;
        }

        public Criteria andSeparationDefClassLessThanOrEqualTo(String value) {
            addCriterion("separation_def_class <=", value, "separationDefClass");
            return (Criteria) this;
        }

        public Criteria andSeparationDefClassLike(String value) {
            addCriterion("separation_def_class like", value, "separationDefClass");
            return (Criteria) this;
        }

        public Criteria andSeparationDefClassNotLike(String value) {
            addCriterion("separation_def_class not like", value, "separationDefClass");
            return (Criteria) this;
        }

        public Criteria andSeparationDefClassIn(List<String> values) {
            addCriterion("separation_def_class in", values, "separationDefClass");
            return (Criteria) this;
        }

        public Criteria andSeparationDefClassNotIn(List<String> values) {
            addCriterion("separation_def_class not in", values, "separationDefClass");
            return (Criteria) this;
        }

        public Criteria andSeparationDefClassBetween(String value1, String value2) {
            addCriterion("separation_def_class between", value1, value2, "separationDefClass");
            return (Criteria) this;
        }

        public Criteria andSeparationDefClassNotBetween(String value1, String value2) {
            addCriterion("separation_def_class not between", value1, value2, "separationDefClass");
            return (Criteria) this;
        }

        public Criteria andFileHeaderInfoClassIsNull() {
            addCriterion("file_header_info_class is null");
            return (Criteria) this;
        }

        public Criteria andFileHeaderInfoClassIsNotNull() {
            addCriterion("file_header_info_class is not null");
            return (Criteria) this;
        }

        public Criteria andFileHeaderInfoClassEqualTo(String value) {
            addCriterion("file_header_info_class =", value, "fileHeaderInfoClass");
            return (Criteria) this;
        }

        public Criteria andFileHeaderInfoClassNotEqualTo(String value) {
            addCriterion("file_header_info_class <>", value, "fileHeaderInfoClass");
            return (Criteria) this;
        }

        public Criteria andFileHeaderInfoClassGreaterThan(String value) {
            addCriterion("file_header_info_class >", value, "fileHeaderInfoClass");
            return (Criteria) this;
        }

        public Criteria andFileHeaderInfoClassGreaterThanOrEqualTo(String value) {
            addCriterion("file_header_info_class >=", value, "fileHeaderInfoClass");
            return (Criteria) this;
        }

        public Criteria andFileHeaderInfoClassLessThan(String value) {
            addCriterion("file_header_info_class <", value, "fileHeaderInfoClass");
            return (Criteria) this;
        }

        public Criteria andFileHeaderInfoClassLessThanOrEqualTo(String value) {
            addCriterion("file_header_info_class <=", value, "fileHeaderInfoClass");
            return (Criteria) this;
        }

        public Criteria andFileHeaderInfoClassLike(String value) {
            addCriterion("file_header_info_class like", value, "fileHeaderInfoClass");
            return (Criteria) this;
        }

        public Criteria andFileHeaderInfoClassNotLike(String value) {
            addCriterion("file_header_info_class not like", value, "fileHeaderInfoClass");
            return (Criteria) this;
        }

        public Criteria andFileHeaderInfoClassIn(List<String> values) {
            addCriterion("file_header_info_class in", values, "fileHeaderInfoClass");
            return (Criteria) this;
        }

        public Criteria andFileHeaderInfoClassNotIn(List<String> values) {
            addCriterion("file_header_info_class not in", values, "fileHeaderInfoClass");
            return (Criteria) this;
        }

        public Criteria andFileHeaderInfoClassBetween(String value1, String value2) {
            addCriterion("file_header_info_class between", value1, value2, "fileHeaderInfoClass");
            return (Criteria) this;
        }

        public Criteria andFileHeaderInfoClassNotBetween(String value1, String value2) {
            addCriterion("file_header_info_class not between", value1, value2, "fileHeaderInfoClass");
            return (Criteria) this;
        }

        public Criteria andSqlOutTableNameIsNull() {
            addCriterion("sql_out_table_name is null");
            return (Criteria) this;
        }

        public Criteria andSqlOutTableNameIsNotNull() {
            addCriterion("sql_out_table_name is not null");
            return (Criteria) this;
        }

        public Criteria andSqlOutTableNameEqualTo(String value) {
            addCriterion("sql_out_table_name =", value, "sqlOutTableName");
            return (Criteria) this;
        }

        public Criteria andSqlOutTableNameNotEqualTo(String value) {
            addCriterion("sql_out_table_name <>", value, "sqlOutTableName");
            return (Criteria) this;
        }

        public Criteria andSqlOutTableNameGreaterThan(String value) {
            addCriterion("sql_out_table_name >", value, "sqlOutTableName");
            return (Criteria) this;
        }

        public Criteria andSqlOutTableNameGreaterThanOrEqualTo(String value) {
            addCriterion("sql_out_table_name >=", value, "sqlOutTableName");
            return (Criteria) this;
        }

        public Criteria andSqlOutTableNameLessThan(String value) {
            addCriterion("sql_out_table_name <", value, "sqlOutTableName");
            return (Criteria) this;
        }

        public Criteria andSqlOutTableNameLessThanOrEqualTo(String value) {
            addCriterion("sql_out_table_name <=", value, "sqlOutTableName");
            return (Criteria) this;
        }

        public Criteria andSqlOutTableNameLike(String value) {
            addCriterion("sql_out_table_name like", value, "sqlOutTableName");
            return (Criteria) this;
        }

        public Criteria andSqlOutTableNameNotLike(String value) {
            addCriterion("sql_out_table_name not like", value, "sqlOutTableName");
            return (Criteria) this;
        }

        public Criteria andSqlOutTableNameIn(List<String> values) {
            addCriterion("sql_out_table_name in", values, "sqlOutTableName");
            return (Criteria) this;
        }

        public Criteria andSqlOutTableNameNotIn(List<String> values) {
            addCriterion("sql_out_table_name not in", values, "sqlOutTableName");
            return (Criteria) this;
        }

        public Criteria andSqlOutTableNameBetween(String value1, String value2) {
            addCriterion("sql_out_table_name between", value1, value2, "sqlOutTableName");
            return (Criteria) this;
        }

        public Criteria andSqlOutTableNameNotBetween(String value1, String value2) {
            addCriterion("sql_out_table_name not between", value1, value2, "sqlOutTableName");
            return (Criteria) this;
        }

        public Criteria andSqlOutDataIsNull() {
            addCriterion("sql_out_data is null");
            return (Criteria) this;
        }

        public Criteria andSqlOutDataIsNotNull() {
            addCriterion("sql_out_data is not null");
            return (Criteria) this;
        }

        public Criteria andSqlOutDataEqualTo(String value) {
            addCriterion("sql_out_data =", value, "sqlOutData");
            return (Criteria) this;
        }

        public Criteria andSqlOutDataNotEqualTo(String value) {
            addCriterion("sql_out_data <>", value, "sqlOutData");
            return (Criteria) this;
        }

        public Criteria andSqlOutDataGreaterThan(String value) {
            addCriterion("sql_out_data >", value, "sqlOutData");
            return (Criteria) this;
        }

        public Criteria andSqlOutDataGreaterThanOrEqualTo(String value) {
            addCriterion("sql_out_data >=", value, "sqlOutData");
            return (Criteria) this;
        }

        public Criteria andSqlOutDataLessThan(String value) {
            addCriterion("sql_out_data <", value, "sqlOutData");
            return (Criteria) this;
        }

        public Criteria andSqlOutDataLessThanOrEqualTo(String value) {
            addCriterion("sql_out_data <=", value, "sqlOutData");
            return (Criteria) this;
        }

        public Criteria andSqlOutDataLike(String value) {
            addCriterion("sql_out_data like", value, "sqlOutData");
            return (Criteria) this;
        }

        public Criteria andSqlOutDataNotLike(String value) {
            addCriterion("sql_out_data not like", value, "sqlOutData");
            return (Criteria) this;
        }

        public Criteria andSqlOutDataIn(List<String> values) {
            addCriterion("sql_out_data in", values, "sqlOutData");
            return (Criteria) this;
        }

        public Criteria andSqlOutDataNotIn(List<String> values) {
            addCriterion("sql_out_data not in", values, "sqlOutData");
            return (Criteria) this;
        }

        public Criteria andSqlOutDataBetween(String value1, String value2) {
            addCriterion("sql_out_data between", value1, value2, "sqlOutData");
            return (Criteria) this;
        }

        public Criteria andSqlOutDataNotBetween(String value1, String value2) {
            addCriterion("sql_out_data not between", value1, value2, "sqlOutData");
            return (Criteria) this;
        }

        public Criteria andSqlColumnDefIsNull() {
            addCriterion("sql_column_def is null");
            return (Criteria) this;
        }

        public Criteria andSqlColumnDefIsNotNull() {
            addCriterion("sql_column_def is not null");
            return (Criteria) this;
        }

        public Criteria andSqlColumnDefEqualTo(String value) {
            addCriterion("sql_column_def =", value, "sqlColumnDef");
            return (Criteria) this;
        }

        public Criteria andSqlColumnDefNotEqualTo(String value) {
            addCriterion("sql_column_def <>", value, "sqlColumnDef");
            return (Criteria) this;
        }

        public Criteria andSqlColumnDefGreaterThan(String value) {
            addCriterion("sql_column_def >", value, "sqlColumnDef");
            return (Criteria) this;
        }

        public Criteria andSqlColumnDefGreaterThanOrEqualTo(String value) {
            addCriterion("sql_column_def >=", value, "sqlColumnDef");
            return (Criteria) this;
        }

        public Criteria andSqlColumnDefLessThan(String value) {
            addCriterion("sql_column_def <", value, "sqlColumnDef");
            return (Criteria) this;
        }

        public Criteria andSqlColumnDefLessThanOrEqualTo(String value) {
            addCriterion("sql_column_def <=", value, "sqlColumnDef");
            return (Criteria) this;
        }

        public Criteria andSqlColumnDefLike(String value) {
            addCriterion("sql_column_def like", value, "sqlColumnDef");
            return (Criteria) this;
        }

        public Criteria andSqlColumnDefNotLike(String value) {
            addCriterion("sql_column_def not like", value, "sqlColumnDef");
            return (Criteria) this;
        }

        public Criteria andSqlColumnDefIn(List<String> values) {
            addCriterion("sql_column_def in", values, "sqlColumnDef");
            return (Criteria) this;
        }

        public Criteria andSqlColumnDefNotIn(List<String> values) {
            addCriterion("sql_column_def not in", values, "sqlColumnDef");
            return (Criteria) this;
        }

        public Criteria andSqlColumnDefBetween(String value1, String value2) {
            addCriterion("sql_column_def between", value1, value2, "sqlColumnDef");
            return (Criteria) this;
        }

        public Criteria andSqlColumnDefNotBetween(String value1, String value2) {
            addCriterion("sql_column_def not between", value1, value2, "sqlColumnDef");
            return (Criteria) this;
        }

        public Criteria andSqlWhereDefIsNull() {
            addCriterion("sql_where_def is null");
            return (Criteria) this;
        }

        public Criteria andSqlWhereDefIsNotNull() {
            addCriterion("sql_where_def is not null");
            return (Criteria) this;
        }

        public Criteria andSqlWhereDefEqualTo(String value) {
            addCriterion("sql_where_def =", value, "sqlWhereDef");
            return (Criteria) this;
        }

        public Criteria andSqlWhereDefNotEqualTo(String value) {
            addCriterion("sql_where_def <>", value, "sqlWhereDef");
            return (Criteria) this;
        }

        public Criteria andSqlWhereDefGreaterThan(String value) {
            addCriterion("sql_where_def >", value, "sqlWhereDef");
            return (Criteria) this;
        }

        public Criteria andSqlWhereDefGreaterThanOrEqualTo(String value) {
            addCriterion("sql_where_def >=", value, "sqlWhereDef");
            return (Criteria) this;
        }

        public Criteria andSqlWhereDefLessThan(String value) {
            addCriterion("sql_where_def <", value, "sqlWhereDef");
            return (Criteria) this;
        }

        public Criteria andSqlWhereDefLessThanOrEqualTo(String value) {
            addCriterion("sql_where_def <=", value, "sqlWhereDef");
            return (Criteria) this;
        }

        public Criteria andSqlWhereDefLike(String value) {
            addCriterion("sql_where_def like", value, "sqlWhereDef");
            return (Criteria) this;
        }

        public Criteria andSqlWhereDefNotLike(String value) {
            addCriterion("sql_where_def not like", value, "sqlWhereDef");
            return (Criteria) this;
        }

        public Criteria andSqlWhereDefIn(List<String> values) {
            addCriterion("sql_where_def in", values, "sqlWhereDef");
            return (Criteria) this;
        }

        public Criteria andSqlWhereDefNotIn(List<String> values) {
            addCriterion("sql_where_def not in", values, "sqlWhereDef");
            return (Criteria) this;
        }

        public Criteria andSqlWhereDefBetween(String value1, String value2) {
            addCriterion("sql_where_def between", value1, value2, "sqlWhereDef");
            return (Criteria) this;
        }

        public Criteria andSqlWhereDefNotBetween(String value1, String value2) {
            addCriterion("sql_where_def not between", value1, value2, "sqlWhereDef");
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