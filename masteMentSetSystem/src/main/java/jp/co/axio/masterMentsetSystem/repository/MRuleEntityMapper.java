package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;

import jp.co.axio.masterMentsetSystem.dto.RuleConditionSetDto;
import jp.co.axio.masterMentsetSystem.model.MRuleEntity;
import jp.co.axio.masterMentsetSystem.model.MRuleEntityExample;
import jp.co.axio.masterMentsetSystem.model.VMRuleDetailEntity;

import org.apache.commons.lang3.StringUtils;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.SelectKey;
import org.apache.ibatis.annotations.SelectProvider;
import org.apache.ibatis.annotations.Update;
import org.apache.ibatis.jdbc.SQL;

@Mapper
public interface MRuleEntityMapper {

    long countByExample(MRuleEntityExample example);

    int deleteByExample(MRuleEntityExample example);

    int deleteByPrimaryKey(String ruleId);

    int insert(MRuleEntity record);

    int insertSelective(MRuleEntity record);

    List<MRuleEntity> selectByExample(MRuleEntityExample example);

    MRuleEntity selectByPrimaryKey(String ruleId);

    int updateByExampleSelective(@Param("record") MRuleEntity record, @Param("example") MRuleEntityExample example);

    int updateByExample(@Param("record") MRuleEntity record, @Param("example") MRuleEntityExample example);

    int updateByPrimaryKeySelective(MRuleEntity record);

    int updateByPrimaryKey(MRuleEntity record);

    @Select("SELECT count(*) FROM m_rule WHERE rule_id = #{ruleId}")
    int countRuleRec( String ruleId );

    @Insert("INSERT INTO m_rule (rule_id, rule_name, note, start_date, end_date, invalid_flag, register_id, regist_ts, updater_id, update_ts) "
    		+ "VALUES ( #{mRule.ruleId}, #{mRule.ruleName}, #{mRule.note}, #{mRule.startDate}, #{mRule.endDate}, #{mRule.invalidFlag}, "
    		+ "'online', current_timestamp, 'online', current_timestamp) ")
//    @SelectKey(statement = "SELECT lpad(cast(nextVal('m_rule_id_seq'), 5, '0')", keyProperty = "mRule.ruleId", before = true, resultType = String.class)
    public int insertToRule(@Param("mRule") MRuleEntity mRule);

    @Update("UPDATE m_rule SET invalid_flag='1', updater_id='online', update_ts=current_timestamp WHERE rule_id = #{ruleId} ")
    public int deleteRule(@Param("ruleId") String ruleId);

    @Update("UPDATE m_rule SET rule_name=#{mRule.ruleName}, note=#{mRule.note}, start_date=#{mRule.startDate}, end_date=#{mRule.endDate}, invalid_flag=#{mRule.invalidFlag}, "
    		+ "register_id='online', regist_ts=current_timestamp, updater_id='online', update_ts=current_timestamp "
    		+ "WHERE rule_id = #{mRule.ruleId} ")
    public int updateRule(@Param("mRule") MRuleEntity mRule);

    @Select("SELECT nextVal('m_rule_id_seq') ")
    public long nextRuleId();

	/**
     * グループの対応ルール情報を取得する
     *
     * @param systemBaseDate
     * @return
     */
    List<MRuleEntity> selectGroupRuleList(@Param("groupId")String groupId);

	/**
     * ルール情報検索結果一覧を取得する
     *
     * @return
     */
    @SelectProvider(type = RuleSqlProvider.class, method = "selectRuleList")
    public List<RuleConditionSetDto> selectRuleList(
    			@Param("ruleId") String ruleId,
    			@Param("ruleName") String ruleName,
    			@Param("ruleNote") String ruleNote,
    			@Param("refDate") java.sql.Date refDate);

    static class RuleSqlProvider  extends SQL {

        public  String  selectRuleList(
    			@Param("ruleId") String ruleId,
    			@Param("ruleName") String ruleName,
    			@Param("ruleNote") String ruleNote,
    			@Param("refDate") java.sql.Date refDate) {

            StringBuilder sql = new StringBuilder(
            		"SELECT DISTINCT rule_id, rule_name, note, to_char(start_date, 'YYYY/MM/DD') as start_date, to_char(end_date, 'YYYY/MM/DD') as end_date FROM m_rule WHERE invalid_flag = '0'");
            String orderby = " order by rule_id, rule_name, start_date,  end_date ";

            if (ruleId != null && ruleId.length() > 0) {
            	sql.append(" and rule_id like #{ruleId} ");
            }
            if (ruleName != null && ruleName.length() > 0) {
            	sql.append(" and rule_name like #{ruleName} ");
            }
            if (ruleNote != null && ruleNote.length() > 0) {
            	sql.append(" and note like #{ruleNote} ");
            }
            if (refDate != null) {
            	sql.append(" and #{refDate} between start_date and end_date ");
            }
            return sql.toString() + orderby;
        }
    }
}