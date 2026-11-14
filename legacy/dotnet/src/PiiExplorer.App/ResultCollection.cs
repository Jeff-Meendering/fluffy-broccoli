using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;

namespace PiiExplorer.App;

internal sealed class ResultCollection<T> : ObservableCollection<T>
{
    public void Append(IReadOnlyList<T> values)
    {
        if (values.Count < 128) { foreach (var value in values) Add(value); return; }
        CheckReentrancy();
        foreach (var value in values) Items.Add(value);
        Reset();
    }

    public void Replace(IEnumerable<T> values)
    {
        CheckReentrancy(); Items.Clear();
        foreach (var value in values) Items.Add(value);
        Reset();
    }

    private void Reset()
    {
        OnPropertyChanged(new PropertyChangedEventArgs(nameof(Count)));
        OnPropertyChanged(new PropertyChangedEventArgs("Item[]"));
        OnCollectionChanged(new NotifyCollectionChangedEventArgs(NotifyCollectionChangedAction.Reset));
    }
}
