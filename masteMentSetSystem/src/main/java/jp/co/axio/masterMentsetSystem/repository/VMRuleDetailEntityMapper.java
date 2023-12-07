package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;

import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Select;

import jp.co.axio.masterMentsetSystem.model.MRuleGroupEntity;
import jp.co.axio.masterMentsetSystem.model.VMRuleDetailEntity;

@Mapper
public interface VMRuleDetailEntityMapper {

    @Select("SELECT * FROM v_m_rule_detail WHERE rule_id = #{ruleId} order by rule_id, rule_detail_id, rule_detail_flag")
    List<VMRuleDetailEntity> selectVMRuleDetail( String ruleId );

    @Select("SELECT * FROM v_m_rule_detail order by rule_id, rule_detail_id, rule_detail_flag")
    List<VMRuleDetailEntity> selectAllVMRuleDetail( );

    @Select("SELECT * FROM m_rule_group where rule_id = #{ruleId} order by rule_id, group_id")
    List<MRuleGroupEntity> selectMRuleGroupMst( String ruleId );

}