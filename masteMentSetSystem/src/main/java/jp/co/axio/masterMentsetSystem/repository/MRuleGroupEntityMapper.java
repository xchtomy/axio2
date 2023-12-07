package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;

import jp.co.axio.masterMentsetSystem.model.MRuleDetailEntity;
import jp.co.axio.masterMentsetSystem.model.MRuleGroupEnRec;
import jp.co.axio.masterMentsetSystem.model.MRuleGroupEntity;
import jp.co.axio.masterMentsetSystem.model.MRuleGroupEntityExample;
import jp.co.axio.masterMentsetSystem.model.MRuleGroupEntityKey;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

@Mapper
public interface MRuleGroupEntityMapper {
    long countByExample(MRuleGroupEntityExample example);

    int deleteByExample(MRuleGroupEntityExample example);

    int deleteByPrimaryKey(MRuleGroupEntityKey key);

    int insert(MRuleGroupEntity record);

    int insertSelective(MRuleGroupEntity record);

    List<MRuleGroupEntity> selectByExample(MRuleGroupEntityExample example);

    MRuleGroupEntity selectByPrimaryKey(MRuleGroupEntityKey key);

    int updateByExampleSelective(@Param("record") MRuleGroupEntity record, @Param("example") MRuleGroupEntityExample example);

    int updateByExample(@Param("record") MRuleGroupEntity record, @Param("example") MRuleGroupEntityExample example);

    int updateByPrimaryKeySelective(MRuleGroupEntity record);

    int updateByPrimaryKey(MRuleGroupEntity record);

    @Select("SELECT * FROM m_rule_group WHERE rule_id = #{ruleId}" )
    List<MRuleGroupEntity> selectRuleGroup(@Param("ruleId") String ruleId );

    @Delete("DELETE FROM m_rule_group WHERE rule_id = #{ruleId}" )
    int deleteRuleGroup(@Param("ruleId") String ruleId );

    @Select("SELECT rg.rule_id, rg.group_id, rg.register_id, rg.regist_ts, rg.updater_id, rg.update_ts, gp.group_name_en, gp.group_name_jp, "
    		+ "gp.start_date, gp.end_date, gp.note, gp.invalid_flag FROM m_rule_group rg "
    		+ "LEFT JOIN m_group gp ON rg.group_id=gp.group_id WHERE rule_id = #{ruleId}" )
    List<MRuleGroupEnRec> selectRuleJoinGroup(@Param("ruleId") String ruleId);

    @Insert("INSERT INTO m_rule_group (rule_id, group_id, register_id, regist_ts, updater_id, update_ts) "
    		+ "VALUES ( #{mrg.ruleId}, #{mrg.groupId}, 'online', current_timestamp, 'online', current_timestamp) ")
    public int insertToRuleGroup(@Param("mrg") MRuleGroupEntity mrg);
}