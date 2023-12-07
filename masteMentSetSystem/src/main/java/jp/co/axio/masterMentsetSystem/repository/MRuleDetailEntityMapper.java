package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import jp.co.axio.masterMentsetSystem.model.MRuleDetailEntity;
import jp.co.axio.masterMentsetSystem.model.MRuleDetailEntityExample;
import jp.co.axio.masterMentsetSystem.model.MRuleDetailEntityKey;

@Mapper
public interface MRuleDetailEntityMapper {
    long countByExample(MRuleDetailEntityExample example);

    int deleteByExample(MRuleDetailEntityExample example);

    int deleteByPrimaryKey(MRuleDetailEntityKey key);

    int insert(MRuleDetailEntity record);

    int insertSelective(MRuleDetailEntity record);

    List<MRuleDetailEntity> selectByExample(MRuleDetailEntityExample example);

    MRuleDetailEntity selectByPrimaryKey(MRuleDetailEntityKey key);

    int updateByExampleSelective(@Param("record") MRuleDetailEntity record, @Param("example") MRuleDetailEntityExample example);

    int updateByExample(@Param("record") MRuleDetailEntity record, @Param("example") MRuleDetailEntityExample example);

    int updateByPrimaryKeySelective(MRuleDetailEntity record);

    int updateByPrimaryKey(MRuleDetailEntity record);

    @Select("SELECT count(*) FROM m_rule_detail WHERE rule_id = #{ruleId}" )
    int countRuleDetailRec( String ruleId );

    @Select("SELECT * FROM m_rule_detail WHERE rule_id = #{ruleId}" )
    List<MRuleDetailEntity> selectRuleDetail(@Param("ruleId") String ruleId );

    @Delete("DELETE FROM m_rule_detail WHERE rule_id = #{ruleId}" )
    int deleteRuleDetail(@Param("ruleId") String ruleId );

    @Insert("INSERT INTO m_rule_detail (rule_id, rule_detail_id, rule_detail_flag, company_code, organization_code, employment_kbn, position_code, register_id, regist_ts, updater_id, update_ts) "
    		+ "VALUES ( #{mrd.ruleId}, #{mrd.ruleDetailId}, #{mrd.ruleDetailFlag}, #{mrd.companyCode}, #{mrd.organizationCode}, #{mrd.employmentKbn}, #{mrd.positionCode},"
    		+ "'online', current_timestamp, 'online', current_timestamp) ")
    public int insertToRuleDetail(@Param("mrd") MRuleDetailEntity mrd);
}