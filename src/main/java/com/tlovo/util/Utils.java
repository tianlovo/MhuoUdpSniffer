package com.tlovo.util;

import com.tlovo.analyze.packet.CmdId;
import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.HashMap;
import java.util.Map;

@Slf4j
public class Utils {

    /**
     * 提取CmdId类定义的所有CmdId变量
     * @return <变量值,变量名>
     */
    public static Map<Integer, String> extractCmdIds() {
        Map<Integer, String> variableMap = new HashMap<>();
        Class<?> cls = CmdId.class;

        Field[] fields = cls.getDeclaredFields();
        for (Field field : fields) {
            if (Modifier.isPublic(field.getModifiers()) &&
                    Modifier.isStatic(field.getModifiers()) &&
                    Modifier.isFinal(field.getModifiers()) &&
                    field.getType() == int.class) {

                try {
                    int value = field.getInt(null);
                    String name = field.getName();
                    variableMap.put(value, name);
                } catch (IllegalAccessException e) {
                    log.warn("非法的访问权限", e);
                }
            }
        }

        return variableMap;
    }
}
