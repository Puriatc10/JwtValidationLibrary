using System;
using System.Collections.Generic;

public static class DataStorage
{
    private static HashSet<string> dataSet = new HashSet<string>();

    public static void StoreData(string data)
    {
        dataSet.Add(data);
    }

    public static bool ContainsData(string data)
    {
        return dataSet.Contains(data);
    }

    public static void RemoveData(string data)
    {
        dataSet.Remove(data);
    }
}
