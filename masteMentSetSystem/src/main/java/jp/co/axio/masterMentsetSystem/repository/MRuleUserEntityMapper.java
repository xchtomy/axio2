package jp.co.axio.masterMentsetSystem.repository;

import java.util.List;

import org.apache.ibatis.annotations.Delete;
import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import jp.co.axio.masterMentsetSystem.model.MRuleUserEntity;
import jp.co.axio.masterMentsetSystem.model.MRuleUserEntityExample;
import jp.co.axio.masterMentsetSystem.model.MRuleUserEntityKey;

@Mapper
public interface MRuleUserEntityMapper {
    long countByExample(MRuleUserEntityExample example);

    int deleteByExample(MRuleUserEntityExample example);

    int deleteByPrimaryKey(MRuleUserEntityKey key);

    int insert(MRuleUserEntity row);

    int insertSelective(MRuleUserEntity row);

    List<MRuleUserEntity> selectByExample(MRuleUserEntityExample example);

    MRuleUserEntity selectByPrimaryKey(MRuleUserEntityKey key);

    int updateByExampleSelective(@Param("row") MRuleUserEntity row, @Param("example") MRuleUserEntityExample example);

    int updateByExample(@Param("row") MRuleUserEntity row, @Param("example") MRuleUserEntityExample example);

    int updateByPrimaryKeySelective(MRuleUserEntity row);

    int updateByPrimaryKey(MRuleUserEntity row);

    @Delete("DELETE FROM m_rule_user WHERE rule_id = #{ruleId}" )
    int deleteRuleUser(@Param("ruleId") String ruleId );

    @Select("select ru.rule_id, concat(ru.user_id, ':', mg.surname_jp, ' ', mg.givenname_jp) as user_id, exclusion_flag  "
    		+ "from m_rule_user ru "
    		+ "left join m_user mg on ru.user_id = mg.user_id WHERE rule_id = #{ruleId} order by ru.user_id " )
    List<MRuleUserEntity> selectRuleJoinUser(@Param("ruleId") String ruleId);

    @Insert("INSERT INTO m_rule_user (rule_id, user_id, exclusion_flag, register_id, regist_ts, updater_id, update_ts) "
    		+ "VALUES ( #{mru.ruleId}, #{mru.userId}, #{mru.exclusionFlag}, 'online', current_timestamp, 'online', current_timestamp) ")
    public int insertToRuleUser(@Param("mru") MRuleUserEntity mru);

}